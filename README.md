# Gallery Vault Decryptor

Recovery tool for assets encrypted by the Gallery Vault (ThinkYeah) Android
application. It supports the V2 container layout documented below and does not
require the Gallery Vault PIN.

Only recover data that you own or are authorized to examine.

## Requirements

- Python 3.10 or newer
- PyCryptodome for the format's DES operations
- prompt-toolkit for the terminal interface

Install the runtime dependencies:

```bash
python3 -m pip install -r requirements.txt
```

For development and tests:

```bash
python3 -m pip install -r requirements-dev.txt
ruff format --check .
ruff check .
python3 -m pytest
```

## Usage

### Interactive terminal interface

```bash
python3 gv_tui.py
```

Select a dump directory or an individual encrypted file, review the output
directory, and press F5 or choose **Recover**. F10 requests a safe stop while a
recovery is active and exits when idle.

Smart discovery looks for directories named like
`.galleryvault_DoNotDelete_123` and processes their `files` directory. Disable
it to inspect every file beneath the selected path.

### Batch CLI

```bash
python3 gv_decryptor.py /path/to/dump --out /path/to/output
```

Useful options:

```text
--manual, --scan-all  Scan all files instead of discovering repositories
--no-recursive       Only scan or discover at the top level
--overwrite          Replace existing recovered files
--verbose            Show skipped files and detailed status counts
```

An individual encrypted file is also accepted:

```bash
python3 gv_decryptor.py encrypted_asset --manual
```

If `--out` is omitted, recovered files go to `INPUT_recovered`. The input tree
is preserved beneath that directory. Existing files are not overwritten unless
`--overwrite` is provided, and output is written atomically so a failed or
cancelled recovery does not leave a partial recovered file.

CLI exit codes are:

- `0`: at least one asset was recovered and no candidate failed
- `1`: no assets were recovered, or at least one candidate failed
- `2`: invalid input or output configuration

## Supported output detection

The recovered extension is selected from the file signature. The built-in
detector recognizes PNG, JPEG, GIF, WebP, MP4, MOV, 3GP, HEIC/HEIF, AVIF, MP3,
WAV, Ogg, AVI, Matroska, PDF, and ZIP. Unknown content is written as `.bin`.

## How it works

In the supported Gallery Vault V2 format, the PIN protects the application UI;
the file payload uses a position-dependent XOR transform. Its per-file key is
stored in the container after being encrypted with a DES key derived from
constants used by the application.

A simplified container layout is:

```text
┌──────────────────── Gallery Vault V2 container ────────────────────┐
│ Thumbnail prefix │ Encrypted payload                               │
├────────────────────────────────────────────────────────────────────┤
│ Inner marker  >>tyfs>>                                             │
│ Optional swapped payload block                                     │
├─────────────────────────── Tail metadata ──────────────────────────┤
│ Thumbnail length              8 bytes                              │
│ Payload/marker boundary       8 bytes                              │
│ Layout selector               1 byte                               │
│ DES-encrypted XOR key         variable, block aligned              │
│ Encrypted-key length          8 bytes                              │
│ Metadata                      variable                             │
│ Metadata length               8 bytes                              │
│ Version field                 2 bytes (01 01)                      │
├────────────────────────────────────────────────────────────────────┤
│ End marker  <<tyfs<<                                               │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
      validate offsets → recover XOR key → assemble payload
                              │
                              ▼
                    stream recovered asset
```

The decryptor validates these offsets and markers before processing a payload.
It then decrypts the per-file key, assembles the payload ranges selected by the
layout byte, and applies:

```text
plain[i] = encrypted[i] XOR (i & 0xff) XOR key[i mod key_length]
```

Files are transformed in chunks, which keeps memory usage bounded for large
videos. Smart discovery and all-file scanning use the same implementation in
the CLI and TUI.

## Compatibility and troubleshooting

- `UNSUPPORTED_VERSION` means the file has Gallery Vault markers but does not
  contain the supported V2 version field.
- `CORRUPT_STRUCTURE` means a marker, length, or payload boundary is invalid.
- `NOT_GV` means the Gallery Vault end marker was not found near the file tail.
- `EXISTS` means the destination was preserved; use `--overwrite` only when the
  replacement is intentional.
- Use `--verbose` when scanning a mixed directory to see detailed statuses.

Gallery Vault has had multiple releases and storage layouts. Compatibility is
limited to files matching the V2 structure above; keep the original encrypted
data until the recovered files have been verified.

## Disclaimer

This tool is provided for educational and forensic purposes only. The author
bears no responsibility for misuse. Always ensure you have proper authorization
before decrypting data that does not belong to you.
