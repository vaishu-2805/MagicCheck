# MagicCheck

A security tool that detects suspicious files by comparing their magic bytes (file signatures) with their extensions.

## Problem Statement

Hackers often disguise malicious files by changing their extensions (e.g., renaming `virus.exe` to `photo.jpg`). While operating systems and users may trust files based on their extensions, the true file type is determined by the file's magic bytes (headers). This creates a security risk where malware can be hidden behind misleading extensions.

## Features

- ✅ Detects file type by reading magic bytes (first few bytes)
- ✅ Compares actual file type with claimed extension
- ✅ Flags mismatches as suspicious
- ✅ Includes common file signatures (JPG, PNG, PDF, EXE, ZIP, etc.)
- ✅ Generates SHA256 hash for potential malware database checks

## Usage

1. Run the script:

```bash
python magic_check.py
```

2. Enter the path to the file you want to check when prompted.

3. The tool will analyze the file and display:
   - Claimed extension
   - Actual file type based on magic bytes
   - Whether the file is suspicious
   - SHA256 hash of the file

## Supported File Types

Currently supports detection of:

- JPG/JPEG
- PNG
- PDF
- EXE
- ZIP
- ELF
- RAR
- GIF

## Security Note

This tool is for educational and preliminary analysis purposes. While it can help identify suspicious files, it should not be the only security measure you rely on. Always use comprehensive antivirus software and follow proper security practices.

## Requirements

- Python 3.x
- Standard library modules (no additional installations required):
  - os
  - struct
  - hashlib
