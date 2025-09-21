# MagicCheck - Advanced File Analysis Tool

## Overview

MagicCheck is a sophisticated file analysis tool designed to detect suspicious and potentially malicious files through multiple analysis techniques. It combines file signature analysis, entropy calculation, steganography detection, and various heuristic checks to provide a comprehensive security assessment.

## Features

### Core Features

- Advanced file type detection using magic numbers and multiple fallbacks
- Entropy analysis with type-specific thresholds
- Enhanced steganography detection in images
- Advanced image analysis with format-specific checks
- Archive content analysis (ZIP, RAR, 7z)
- Suspicious pattern detection
- Granular risk scoring system (0-100)

### Analysis Capabilities

- File type verification and mismatch detection
- Advanced image analysis and steganography detection
- Hidden data detection after EOF markers
- Granular compression ratio analysis
- Deep binary content analysis
- Base64 and encoded content detection
- Known malicious pattern matching

### Enhanced Image Analysis

- Format-specific validation (PNG, JPEG, GIF)
- Image dimension verification
- Color channel entropy analysis
- LSB steganography detection
- Size consistency checks
- Anomaly detection in metadata
- Header and marker validation

### Visualization and Reporting

- Colorized CLI output with risk levels
- Detailed scan summaries with percentages
- Multiple report formats (JSON, CSV)
- Risk score breakdown

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/MagicCheck.git
cd MagicCheck
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

For Windows users, additional magic binary might be needed:

```bash
pip install python-magic-bin
```

## Usage

### Basic Usage

Run the script and follow the interactive menu:

```bash
python magic_check.py
```

### Menu Options

1. Scan a single file
2. Scan a directory
3. Exit

### Report Formats

Reports are automatically generated in:

- JSON format (.json)
- CSV format (.csv)

## Risk Score System

| Score Range | Risk Level | Description                            |
| ----------- | ---------- | -------------------------------------- |
| 0-20        | Safe       | No suspicious indicators found         |
| 21-50       | Warning    | Some suspicious elements detected      |
| 51-100      | Dangerous  | Multiple suspicious indicators present |

## Detection Methods

### File Analysis

- Magic number verification
- Entropy calculation
- Extension mismatch detection
- Hidden data detection
- Base64 content detection
- Pattern analysis

### Image Analysis

- Format validation
- Entropy analysis
- Metadata checks
- Steganography detection
- Dimension verification

### Archive Analysis

- Compression ratio verification
- Nested archive detection
- Content size validation
- Format-specific checks

## Supported File Types

### Common Types

- Images: JPG/JPEG, PNG, GIF
- Documents: PDF, DOC/DOCX, XLS/XLSX
- Executables: EXE, DLL
- Archives: ZIP, RAR, 7Z

## Requirements

### Core Dependencies

- Python 3.8+
- colorama: Terminal colors
- python-magic: Enhanced file type detection
- Additional requirements in requirements.txt

## Sample Files

The repository includes:

- img.png: Sample image file for testing image analysis
- anomalous_sample.zip: Sample archive for testing archive analysis

## Security Notes

1. MagicCheck is a supplementary analysis tool, not a replacement for antivirus software
2. Exercise caution with files showing:
   - Hidden data after EOF
   - Abnormal entropy levels
   - Steganography indicators
   - Suspicious patterns
