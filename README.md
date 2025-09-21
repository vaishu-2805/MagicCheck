# MagicCheck

A comprehensive security tool that detects suspicious files through magic bytes analysis, archive inspection, and various anti-obfuscation checks.

## Problem Statement

Hackers often use various techniques to disguise malicious files:

- Changing file extensions (e.g., `virus.exe` → `photo.jpg`)
- Using double extensions (e.g., `document.pdf.exe`)
- Employing Unicode tricks (e.g., using look-alike characters)
- Hiding malware in archives
- Using encryption/packing to obfuscate content

While operating systems and users may trust files based on their extensions, the true file type is determined by the file's magic bytes (headers). This creates multiple security risks that this tool helps identify.

## Features

### Basic File Analysis

- ✅ Detects file type by reading magic bytes (first few bytes)
- ✅ Compares actual file type with claimed extension
- ✅ Generates SHA256 hash for malware database checks
- ✅ Supports many file types (JPG, PNG, PDF, EXE, ZIP, etc.)

### Advanced Security Checks

- ✅ Double extension detection (e.g., `.jpg.exe`)
- ✅ Unicode manipulation detection
- ✅ Entropy analysis for packed/encrypted content
- ✅ Suspicious pattern detection

### Archive Analysis

- ✅ Scans archive contents (ZIP, RAR, etc.)
- ✅ Detects suspicious files inside archives
- ✅ Identifies nested archives
- ✅ Checks for path traversal attempts
- ✅ Analyzes compression ratios
- ✅ Reports file type distribution
- ✅ Entropy checking of archive contents

### Batch Processing

- ✅ Single file analysis
- ✅ Recursive directory scanning
- ✅ Detailed reporting for each file

## Usage

1. Run the script:

```bash
python magic_check.py
```

2. Choose scan type:

   - Single file analysis
   - Directory scanning (recursive)

3. Enter the path to analyze.

4. The tool provides comprehensive analysis including:
   - Basic file information (size, type, hash)
   - Extension verification
   - Suspicious pattern detection
   - Archive content analysis
   - Entropy measurements
   - Detailed security warnings

### Archive Scanning Details

When scanning archives, the tool reports:

- Total number of files
- Size statistics (original/compressed)
- List of suspicious files
- Nested archive detection
- Path traversal attempts
- Compression anomalies
- High-entropy file detection
- File type distribution

## Supported File Types

### Basic File Types

- Images: JPG/JPEG, PNG, GIF
- Documents: PDF, DOC/DOCX, XLS/XLSX
- Executables: EXE, DLL, ELF
- Archives: ZIP, RAR, 7Z, TAR, GZIP

### Archive Analysis

Performs deep inspection of archive contents with:

- Executable detection (.exe, .dll, .bat, etc.)
- Script file detection (.ps1, .vbs, .js, etc.)
- Nested archive analysis
- Compression ratio verification
- Entropy analysis of contents

## Security Notes

1. This tool provides preliminary analysis but should not be your only security measure
2. Always use comprehensive antivirus software
3. Be especially careful with:
   - Files having multiple extensions
   - Archives containing executables
   - Files with unusually high entropy
   - Files using Unicode tricks

## Requirements

- Python 3.x
- Standard library modules:
  - os
  - struct
  - hashlib
  - zipfile
  - math
  - re
