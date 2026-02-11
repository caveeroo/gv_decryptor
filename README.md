# Gallery Vault Decryptor

> Recovery tool for assets encrypted by the **Gallery Vault (ThinkYeah)** Android application.

### Requirements

Install dependencies:

```bash
pip install pycryptodome prompt_toolkit
```

* **pycryptodome** — DES master key operations
* **prompt_toolkit** — TUI interface

### Usage

Simply provide an Android filesystem dump and it will recover all Gallery Vault encrypted files.

**Interactive TUI (recommended):**

```bash
python3 gv_tui.py
```

Controls: F5 to start discovery & recovery, Tab to cycle configuration fields, F10 to exit.

**Batch CLI:**

```bash
python3 gv_decryptor.py /path/to/dump --out /path/to/output
```

Add `--manual` to skip repository discovery and scan all files recursively.

### Features

* **Automated Discovery** — scans dumps for hidden repository patterns
* **Master Key Derivation** — simulates the app’s internal security logic, no PIN required
* **Magic Byte Detection** — restores correct file extensions upon decryption (`.jpg`, `.png`, `.mp4`, …)
* **Dual Interface** — interactive TUI for exploration, CLI for batch scripting

---

## How It Works

Gallery Vault V2 does **not** encrypt files with your PIN. The PIN only locks the UI. The actual encryption is a **per-file XOR cipher** whose key is protected by a **hardcoded DES master key** baked into the APK. This means full recovery is possible on any device dump, no PIN required.

### V2 File Layout

Each encrypted file follows a fixed binary structure:

```
┌───────────────────────────────────────────────────────────────┐
│                    ENCRYPTED FILE (.nomedia)                  │
├──────────────────┬────────────────────────────────────────────┤
│  Thumbnail       │  Encrypted Payload                         │
│  Header          │  (XOR-ciphered asset bytes)                │
│  (variable)      │                                            │
├──────────────────┴────────────────────────────────────────────┤
│                  Inner Marker  >>tyfs>>                       │
├───────────────────────────────────────────────────────────────┤
│  Tail Metadata                                                │
│   ├─ Original file length  (8 bytes)                          │
│   ├─ Thumbnail size        (8 bytes)                          │
│   ├─ Check byte            (1 byte)   → selects decode mode   │
│   └─ Encrypted XOR key     (8 bytes)  → DES-encrypted         │
├───────────────────────────────────────────────────────────────┤
│                  End Marker  <<tyfs<<                         │
└───────────────────────────────────────────────────────────────┘
```

### Decryption Pipeline

The recovery happens in two chained DES stages, then a position-aware XOR pass.

```
╔══════════════════════════════════════════════════════════════════╗
║  STAGE 1 — Master Key Derivation  (same for every file)          ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  hardcoded string "good_gv"                                      ║
║         │                                                        ║
║         ▼  pad/truncate to 8 bytes                               ║
║  ┌─────────────┐                                                 ║
║  │  DES-ECB    │ ◄── hardcoded hex constant (128-bit)            ║
║  │  decrypt    │                                                 ║
║  └──────┬──────┘                                                 ║
║         ▼                                                        ║
║   master_key_str  (plaintext, embedded in APK)                   ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  STAGE 2 — Per-file XOR Key Recovery  (once per encrypted file)  ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  master_key_str[:8]                                              ║
║         │                                                        ║
║         ▼                                                        ║
║  ┌─────────────┐                                                 ║
║  │  DES-ECB    │ ◄── encrypted_xor_key  (8 bytes, from tail)     ║
║  │  decrypt    │                                                 ║
║  └──────┬──────┘                                                 ║
║         ▼  take first 4 bytes                                    ║
║     xor_key  [k0, k1, k2, k3]                                    ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  STAGE 3 — Payload Assembly + XOR Transform                      ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║           ┌───────────────────────────────────────┐              ║
║           │        check_byte  (from tail)        │              ║
║           └─────────────┬────────────────┬────────┘              ║
║                    0x00 │           0x01 │                       ║
║                         ▼                ▼                       ║
║           ┌─────────────────┐  ┌─────────────────────┐           ║
║           │  data[thumb_len │  │  swapped_block      │           ║
║           │    : orig_len]  │  │  (past >>tyfs>>)    │           ║
║           │  (contiguous)   │  │  +  main_block      │           ║
║           └────────┬────────┘  └────────────┬────────┘           ║
║                    └────────────┬───────────┘                    ║
║                                 ▼                                ║
║                         assembled payload                        ║
║                                  │                               ║
║            ┌───────────────────┼───────────────────┐             ║
║            ▼                   ▼                   ▼             ║
║         byte[i]            (i & 0xFF)       xor_key[i % 4]       ║
║       (ciphertext)       (position salt)   (rotating 4-byte      ║
║                                            key from stage 2)     ║
║             │                   │                  │             ║
║             └─────────► XOR ◄───┘                  │             ║
║                          │                         │             ║
║                          └──────────► XOR ◄────────┘             ║
║                                         ▼                        ║
║                                 out[i]  →  Original Asset        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## Disclaimer

This tool is provided for **educational and forensic purposes only**. The author bears no responsibility for misuse. Always ensure you have proper authorization before decrypting data that does not belong to you.
