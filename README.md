<div align="center">

# PHP2Shell

<p>
  <img src="https://img.shields.io/badge/CVE-2026--109618-critical?style=flat-square&color=CC0000" />
  <img src="https://img.shields.io/badge/CVE-2026--109619-critical?style=flat-square&color=CC0000" />
  <img src="https://img.shields.io/badge/CVSS_v4.0-9.2-red?style=flat-square" />
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/dependencies-none-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/auth_required-none-lightgrey?style=flat-square" />
</p>

<p>Unauthenticated remote code execution chain exploiting OOM memory corruption and stale global state in PHP.</p>

<p>Part of the <a href="https://github.com/nostraxiten/AWESOME-CVE-S">AWESOME-CVE'S</a> series.</p>

</div>

---

## Overview

| | CVE-2026-109618 | CVE-2026-109619 |
|---|---|---|
| GHSA | GHSA-w8hw-w9fx-j79w | GHSA-6wmf-4rv5-p3rp |
| CVSS v4.0 | 9.2 (Critical) | 9.2 (Critical) |
| Type | RCE via OOM memory corruption | RCE via stale global state (use-after-free) |
| Role in chain | Main exploit — leak + forge + exec | Write primitive + worker state control |
| Disclosed | October 20, 2026 | October 20, 2026 |
| Patched | October 21, 2026 | October 21, 2026 |
| Fixed in | PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |
| Auth required | None | None |
| LFI required | None | None |

---

## How Each Vulnerability Works

### CVE-2026-109618 — OOM Memory Corruption

PHP enforces `memory_limit` using `longjmp()` to abort requests that exceed it. The flaw is that this interruption can happen while internal PHP request structures are **only partially initialized**. The cleanup routine processes that half-initialized data as valid, leaking raw heap and `libphp` pointers into the `Set-Cookie` response header. An attacker reads those pointers to defeat ASLR, then forges fake internal PHP structures that redirect execution to `zif_system()`.

### CVE-2026-109619 — Stale Global State (Use-After-Free)

PHP worker processes retain internal global state pointing to memory owned by a previous request, even after that memory has been freed. A subsequent request in the same worker can read or branch on those freed regions. In this chain it serves two purposes: the `session.upload_progress` feature acts as the **write primitive** to place forged structures at predictable heap addresses, and deliberate worker rotation via `rotate()` positions that stale state exactly where the OOM corruption stage needs it.

---

## Chain

Neither CVE alone is sufficient for reliable RCE — they are chained:

```
CVE-2026-109619                     CVE-2026-109618
─────────────────────────────       ──────────────────────────────────────────
session.upload_progress         →   write primitive: place forged structs
                                    on heap at predictable offset
rotate() (stale worker state)   →   positions freed memory for OOM to land on

                                    OOM longjmp() → partial init → pointer leak
                                    Stage 1: Zend MM chunk base (heap ASLR)
                                    Stage 2: libphp base (code ASLR)
                                    Stage 3: forge zend_function + HashTable
                                             zval_ptr_dtor() → zif_system(cmd)
                                             GET output file → RCE confirmed
```

---

## Stages

<details>
<summary><strong>rotate() — Worker Preparation (CVE-2026-109619)</strong></summary>
<br>
Forces a fresh PHP worker into a known state by sending a large multipart request that exhausts the current worker, then seeds <code>session.upload_progress</code> with a fixed session ID (<code>attacksessionid0001</code>). This ensures the stale freed memory from the previous request is in the right position for the subsequent OOM stages.
</details>

<details>
<summary><strong>Stage 1 — Heap Base Leak (CVE-2026-109618)</strong></summary>
<br>
A crafted multipart body exceeds <code>memory_limit</code>, triggering <code>longjmp()</code> mid-initialization. The partially initialized session structure leaks raw Zend MM allocator chunk pointers inside the <code>Set-Cookie: PHPSESSID</code> header. <code>chunk_base_from_cookie()</code> scans for userspace heap addresses (<code>0x7F0000000000–0x7FFFFFFFFFFF</code>) aligned to 2 MB boundaries and extracts the Zend chunk base — ASLR layer 1 bypassed.
</details>

<details>
<summary><strong>Stage 2 — libphp Base Leak (CVE-2026-109618)</strong></summary>
<br>
A second OOM request leaks a <code>zval_ptr_dtor</code> function pointer from <code>libphp.so</code> through the same cookie mechanism. <code>libphp_base_from_cookie()</code> identifies it by matching the low 12 bits against the known dtor offset and subtracts to get the libphp load address — ASLR layer 2 bypassed.
</details>

<details>
<summary><strong>Stage 3 — Code Execution (CVE-2026-109618 + CVE-2026-109619)</strong></summary>
<br>
With both bases known, the exploit computes:

- <code>htdata = chunk_base + htdata_offset</code> — address of forged structure in controlled heap  
- <code>zif = libphp_base + zif_offset</code> — address of <code>zif_system()</code> in libphp  

A fake <code>HashTable</code> + <code>zend_function</code> struct is placed via <code>session.upload_progress</code> at that heap address. When <code>zval_ptr_dtor()</code> fires during cleanup, it follows the forged pointers and calls <code>zif_system(cmd)</code>. Output is redirected to a file on the server and retrieved with a plain GET request.
</details>

---

## Target Profiles

| Offset | Bookworm (Debian 12) | Lab |
|---|---|---|
| `htdata` | `0x690D8` | `0x6E0D8` |
| `zif_system` | `0x43A870` | `0x43A870` |
| `zval_ptr_dtor` | `0x613C50` | `0x613C50` |
| `stage1_n` | 841 | 892 |
| `stage2_t` | 406 | 443 |
| `stage2_v` | 16 | 1 |

Custom offsets can be entered manually at runtime, obtained via reverse engineering the target's `libphp.so`.

---

## Requirements

- Python 3.x
- No external dependencies — stdlib only: `socket` `ssl` `struct` `re` `uuid` `threading` `urllib.parse`

---

## Usage

```bash
python3 PHP2shell.py
```

```
[+] Insert the IP address of the domain vulnerable to php2shell (CVE-2026-109618): <target>
[+] PHP endpoint path [/index.php]: /index.php
[+] Command (max 14 bytes) [id>p2sXXX.out]: id>p2sXXX.out
[+] Output path to fetch [/p2sXXX.out]: /p2sXXX.out
[+] Target profile (bookworm/lab) [bookworm]: bookworm
[+] zif_system offset [0x43a870]:
[+] zval_ptr_dtor offset [0x613c50]:
[+] fake-structure offset [0x690d8]:
[+] OOM field size in MB (must exceed memory_limit) [12]:
```

Target format: `http://192.168.1.50`, `https://vulnerable.lab`, or bare IP (defaults to port 80).

> The command is limited to **14 bytes** — it must fit inside the forged structure placed in heap memory. Use output redirection (`id>/tmp/out`) and adjust the fetch path accordingly.

---

## Notes

- Works against any PHP endpoint — no LFI required.
- ASLR is bypassed in two layers: Zend heap (stage 1) then libphp (stage 2).
- Worker rotation runs between every stage to maintain a predictable heap layout.
- Reliability depends on heap layout matching the selected profile. Up to 3–5 attempts per stage with rotation between each.
- The OOM field size (`huge_mb`) must exceed the server's configured `memory_limit`.

---

## Lab Environment

| Component | Details |
|---|---|
| Target | PHP 8.3.x (unpatched, intentionally vulnerable) |
| Server | Apache2 with mod_php |
| OS | Debian 12 Bookworm — isolated NAT VM |
| Attacker | Kali Linux |

---

## Mitigations

- Update PHP to 8.2.35, 8.3.36, 8.4.27 or 8.5.12+
- Set `memory_limit = -1` via `php_admin_value` — prevents OOM trigger (CVE-2026-109618)
- Set `session.upload_progress.enabled = 0` in `php.ini` — removes write primitive (CVE-2026-109619)
- On PHP 8.5: also set `fatal_error_backtraces = 0`
- Enforce multipart request size, part count and nesting limits at the web server or reverse proxy level

---

## References

- [PHP Advisory — GHSA-w8hw-w9fx-j79w (CVE-2026-109618)](https://github.com/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP Advisory — GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)](https://github.com/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP Official Release — 8.3.36 / 8.4.27](https://www.php.net/ChangeLog-8.php)
- [Datadog Security Labs — PHP2Shell walkthrough](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- [Rapid7 — ETR CVE-2026-109618 & CVE-2026-109619](https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/)
- [Palo Alto Unit42 — PHP2Shell Threat Brief](https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/)
- [Tenable — PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
- [CERT-EU Advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018)
- [NCSC — Critical Security Issue Affecting PHP](https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php)

---

## Legal Disclaimer

This tool is provided for **educational and authorized penetration testing purposes only**. Using it against any system without explicit written permission from the owner is illegal and may violate local and international laws. The author assumes no responsibility for misuse or damage caused by this tool. Only use it in environments you own or have written authorization to test.

---

*By [nostraxiten](https://github.com/nostraxiten)*
