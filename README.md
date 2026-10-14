# ConfigMgr CryptDeriveKey Hashcat Module

Hashcat modules for cracking passwords used to encrypt ConfigMgr/MECM/SCCM media variable files. Key derivation follows Microsoft's documented [CryptDeriveKey](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey#remarks) process.

## Supported Modes

| Mode  | Algorithm | CALG_ID    | Hash Prefix        |
|-------|-----------|------------|--------------------|
| 19850 | AES-128   | 0x0000660e | `$sccm$aes128$`   |
| 19860 | AES-256   | 0x00006610 | `$sccm$aes256$`   |

The algorithm is determined by the CALG_ID at bytes 16-19 of the `.var` file header. Check bytes 16-19 (little-endian) to know which mode to use:
- `0e660000` → AES-128 → mode 19850
- `10660000` → AES-256 → mode 19860

## Hash Format

The hash is the hex encoding of the first 40 bytes of the media variables `.var` file:

```
$sccm$aes128$<80 hex chars>
$sccm$aes256$<80 hex chars>
```

Extract with: `xxd -p -l 40 <file>.var | tr -d '\n'` then prepend the appropriate prefix.

## Usage

```bash
# AES-128
hashcat -m 19850 -a 0 '$sccm$aes128$...' wordlist.txt

# AES-256
hashcat -m 19860 -a 0 '$sccm$aes256$...' wordlist.txt
```

## Build Instructions

1. Clone the Hashcat source repository (tested with v7.1.2-919-g7456ea592; this plugin API is not compatible with 6.x)
2. Copy module files into the Hashcat source tree:
   - `module_19850.c` and `module_19860.c` → `src/modules/`
   - `m19850_*.cl` and `m19860_*.cl` → `OpenCL/`
3. Compile Hashcat per BUILD.md (WSL recommended on Windows)

Supported attack modes: 0, 1, 3, 6, 7 (and 9). `-a 4` (PCFG) works but runs on the host because there is no on-device a4 kernel. `-a 12` only works with the word at the start or end of the mask; with the word in the middle it silently cracks nothing.

Note: the built-in self-test runs with a minimal thread count, so it cannot catch work-group or shared-memory bugs. After changing a kernel, also crack the self-test hash with a small wordlist (`-a 0`) and with a literal mask (`-a 3 Password1`).

## Self-Test Hashes

Both modules self-test against password `Password1`:

```
# AES-128 (mode 19850)
$sccm$aes128$0000edec14000000b2320000c03200000e6600000000000011cb54aa3b699f61f86ab312e6fb97ec

# AES-256 (mode 19860)
$sccm$aes256$0000edec14000000b2320000c032000010660000000000003dd6b8bc6cc41f718b07522266e188ce
```

## Author Credit

AES-128 module: Copyright (C) 2022 Christopher Panayi, MWR CyberSec
AES-256 module: Flangvik / TrustedSec (adapted from original)
