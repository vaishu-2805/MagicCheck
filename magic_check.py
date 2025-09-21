#!/usr/bin/env python3

import os
import struct
import hashlib
import re
from typing import Dict, Tuple, Optional, List
from utils import (
    calculate_entropy,
    detect_double_extension,
    detect_unicode_tricks,
    is_potentially_malicious_archive,
    scan_directory,
    get_suspicious_patterns
)

class MagicCheck:
    def __init__(self):
        # Dictionary of known file signatures (magic numbers)
        self.signatures: Dict[bytes, str] = {
            b'\xFF\xD8\xFF': 'JPG/JPEG',
            b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': 'PNG',
            b'\x25\x50\x44\x46': 'PDF',
            b'\x4D\x5A': 'EXE',
            b'\x50\x4B\x03\x04': 'ZIP',
            b'\x7F\x45\x4C\x46': 'ELF',
            b'\x52\x61\x72\x21\x1A\x07': 'RAR',
            b'\x47\x49\x46\x38': 'GIF',
            b'\x37\x7A\xBC\xAF\x27\x1C': '7Z',
            b'\x1F\x8B\x08': 'GZIP',
            b'\x75\x73\x74\x61\x72': 'TAR',
            b'\xD0\xCF\x11\xE0': 'DOC/XLS',
            b'\x50\x4B\x03\x04\x14\x00\x06\x00': 'DOCX/XLSX'
        }
        
        # Extension to type mapping (more comprehensive)
        self.extension_map = {
            # Images
            'jpg': 'JPG/JPEG',
            'jpeg': 'JPG/JPEG',
            'png': 'PNG',
            'gif': 'GIF',
            # Documents
            'pdf': 'PDF',
            'doc': 'DOC/XLS',
            'docx': 'DOCX/XLSX',
            'xls': 'DOC/XLS',
            'xlsx': 'DOCX/XLSX',
            # Executables
            'exe': 'EXE',
            'dll': 'EXE',
            # Archives
            'zip': 'ZIP',
            'rar': 'RAR',
            '7z': '7Z',
            'gz': 'GZIP',
            'tar': 'TAR',
            # Linux
            'elf': 'ELF'
        }
        
        # Entropy thresholds (adjusted based on file types)
        self.entropy_thresholds = {
            'JPG/JPEG': 7.7,    # JPEG compression naturally has high entropy
            'PNG': 7.5,         # PNG compression has high entropy
            'PDF': 7.0,         # PDFs can have high entropy sections
            'ZIP': 7.8,         # Archives naturally have high entropy
            'RAR': 7.8,
            '7Z': 7.8,
            'GZIP': 7.8,
            'default': 7.0      # Default threshold for other types
        }
        
    def read_magic_bytes(self, filepath: str, num_bytes: int = 8) -> Optional[bytes]:
        """Read the first few bytes of a file."""
        try:
            with open(filepath, 'rb') as f:
                return f.read(num_bytes)
        except Exception as e:
            print(f"Error reading file: {e}")
            return None

    def get_file_type(self, magic_bytes: bytes) -> str:
        """Determine file type from magic bytes."""
        for signature, file_type in self.signatures.items():
            if magic_bytes.startswith(signature):
                return file_type
        return "Unknown"

    def get_file_extension(self, filepath: str) -> str:
        """Get the file extension from the filename."""
        return os.path.splitext(filepath)[1].lower().lstrip('.')

    def calculate_hash(self, filepath: str, algorithm: str = 'sha256') -> Optional[str]:
        """Calculate file hash using specified algorithm."""
        try:
            hash_obj = hashlib.new(algorithm)
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            print(f"Error calculating hash: {e}")
            return None

    def analyze_filename(self, filename: str) -> dict:
        """Analyze filename for suspicious patterns."""
        results = {
            "double_extension": detect_double_extension(filename),
            "unicode_tricks": detect_unicode_tricks(filename),
            "suspicious_patterns": []
        }
        
        # Check for suspicious patterns
        for pattern in get_suspicious_patterns():
            if re.search(pattern, filename, re.IGNORECASE):
                results["suspicious_patterns"].append(pattern)
                
        return results

    def is_archive_type(self, file_type: str) -> bool:
        """Check if the file type is an archive format."""
        return file_type in ['ZIP', 'RAR', '7Z', 'GZIP', 'TAR']

    def check_file(self, filepath: str) -> Tuple[bool, dict]:
        """
        Comprehensive file analysis with improved accuracy.
        Returns: (is_suspicious, details_dict)
        """
        if not os.path.exists(filepath):
            return True, {"error": "File not found", "filepath": filepath}

        # Basic file info
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        
        # Read magic bytes
        magic_bytes = self.read_magic_bytes(filepath)
        if not magic_bytes:
            return True, {"error": "Could not read file", "filepath": filepath}

        # Get actual file type and claimed extension
        actual_type = self.get_file_type(magic_bytes)
        claimed_ext = self.get_file_extension(filepath)
        
        # Calculate file hash
        file_hash = self.calculate_hash(filepath)

        # Analyze filename for suspicious patterns
        filename_analysis = self.analyze_filename(filename)

        # Calculate entropy
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                entropy = calculate_entropy(data)
        except:
            entropy = 0.0

        # Check archive contents if applicable
        archive_malicious = False
        if self.is_archive_type(actual_type):
            archive_malicious = is_potentially_malicious_archive(filepath)

        # Determine if file is suspicious (improved logic)
        is_suspicious = False
        reasons = []

        # 1. Check extension mismatch (improved matching)
        if actual_type != "Unknown":
            expected_type = self.extension_map.get(claimed_ext.lower())
            
            # Only flag if we know both the expected and actual types
            if expected_type and expected_type != actual_type:
                # Special cases handling
                if not (
                    # Allow executable extensions to match EXE type
                    (expected_type == 'EXE' and actual_type == 'EXE') or
                    # Allow document formats to cross-match
                    (expected_type in ['DOC/XLS', 'DOCX/XLSX'] and 
                     actual_type in ['DOC/XLS', 'DOCX/XLSX']) or
                    # Allow archive formats to cross-match
                    (self.is_archive_type(expected_type) and 
                     self.is_archive_type(actual_type))
                ):
                    is_suspicious = True
                    reasons.append(f"Extension mismatch: claims to be {expected_type}, but is {actual_type}")

        # 2. Check for suspicious filename patterns (only if truly suspicious)
        if filename_analysis["double_extension"]:
            # Only consider it suspicious if the last extension is executable
            if any(filename.lower().endswith(f".{ext}") 
                   for ext in ["exe", "dll", "bat", "cmd", "ps1", "vbs", "js"]):
                is_suspicious = True
                reasons.append("Executable double extension detected")
            
        if filename_analysis["unicode_tricks"]:
            is_suspicious = True
            reasons.append("Unicode manipulation detected")
            
        if filename_analysis["suspicious_patterns"]:
            # Filter out common false positives
            real_suspicious_patterns = [
                pattern for pattern in filename_analysis["suspicious_patterns"]
                if not (
                    pattern == r'\s{2,}' and filesize < 1024*1024 or  # Allow spaces in small files
                    pattern == r'\.{2,}' and claimed_ext.lower() in ['txt', 'md', 'doc']  # Allow dots in text files
                )
            ]
            if real_suspicious_patterns:
                is_suspicious = True
                reasons.append("Suspicious filename patterns detected")

        # 3. Check entropy (with type-specific thresholds)
        threshold = self.entropy_thresholds.get(actual_type, 
                                              self.entropy_thresholds['default'])
        high_entropy = entropy > threshold
        
        # Only flag high entropy for non-compressed files
        if high_entropy and not (
            actual_type in ['JPG/JPEG', 'PNG', 'ZIP', 'RAR', '7Z', 'GZIP'] or
            filesize < 1024  # Ignore small files
        ):
            is_suspicious = True
            reasons.append(f"Unusually high entropy ({entropy:.2f} > {threshold})")

        # 4. Check archive contents (with improved logic)
        if archive_malicious and self.is_archive_type(actual_type):
            is_suspicious = True
            reasons.append("Suspicious archive contents detected")

        # Prepare detailed report
        return is_suspicious, {
            "filepath": filepath,
            "filename": filename,
            "filesize": filesize,
            "claimed_extension": claimed_ext,
            "actual_type": actual_type,
            "is_suspicious": is_suspicious,
            "suspicious_reasons": reasons,
            "sha256": file_hash,
            "entropy": entropy,
            "filename_analysis": filename_analysis,
            "high_entropy": high_entropy,
            "archive_malicious": archive_malicious if actual_type in ['ZIP', 'RAR'] else None
        }

def print_analysis_report(details: dict) -> None:
    """Print a detailed analysis report."""
    print("\n=== File Analysis Report ===")
    print(f"File: {details.get('filepath')}")
    print(f"Size: {details.get('filesize', 0):,} bytes")
    print(f"Claimed Extension: {details.get('claimed_extension', 'None')}")
    print(f"Actual Type: {details.get('actual_type', 'Unknown')}")
    print(f"SHA256: {details.get('sha256', 'N/A')}")
    print(f"Entropy: {details.get('entropy', 0):.2f}")
    
    print(f"\nSUSPICIOUS: {'YES' if details.get('is_suspicious') else 'NO'}")
    
    if details.get('is_suspicious'):
        print("\n⚠️ WARNINGS:")
        for reason in details.get('suspicious_reasons', []):
            print(f"- {reason}")
            
        # Show detailed analysis
        filename_analysis = details.get('filename_analysis', {})
        if filename_analysis.get('double_extension'):
            print("\n🔍 Double Extension Analysis:")
            print("- File appears to have multiple extensions")
            
        if filename_analysis.get('unicode_tricks'):
            print("\n🔍 Unicode Analysis:")
            print("- Suspicious Unicode characters detected in filename")
            
        if filename_analysis.get('suspicious_patterns'):
            print("\n🔍 Pattern Analysis:")
            print("- Suspicious patterns found in filename:")
            for pattern in filename_analysis['suspicious_patterns']:
                print(f"  - {pattern}")
                
        if details.get('high_entropy'):
            print("\n🔍 Entropy Analysis:")
            print(f"- High entropy detected ({details.get('entropy', 0):.2f})")
            print("- This might indicate encryption or packing")
            
        if details.get('archive_malicious'):
            print("\n🔍 Archive Analysis:")
            print("- Suspicious content detected in archive")
            
        print("\n⚠️ This file may be potentially dangerous!")
        print("Recommendation: Scan with antivirus before opening.")

def main():
    checker = MagicCheck()
    
    # Ask for scan type
    print("\nMagicCheck - Advanced File Analysis Tool")
    print("1. Scan single file")
    print("2. Scan directory")
    choice = input("\nChoose scan type (1/2): ").strip()
    
    files_to_scan = []
    
    if choice == "1":
        # Single file scan
        filepath = input("Enter the path to the file to check: ").strip('" ')
        files_to_scan = [filepath]
    elif choice == "2":
        # Directory scan
        directory = input("Enter the directory path to scan: ").strip('" ')
        print("\nScanning directory...")
        files_to_scan = scan_directory(directory)
        print(f"Found {len(files_to_scan)} files to scan.")
    else:
        print("Invalid choice!")
        return
    
    # Scan all files
    for filepath in files_to_scan:
        is_suspicious, details = checker.check_file(filepath)
        
        if "error" in details:
            print(f"\nError scanning {details.get('filepath')}: {details['error']}")
            continue
            
        print_analysis_report(details)

if __name__ == "__main__":
    main()
