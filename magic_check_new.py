#!/usr/bin/env python3

import os
import struct
import hashlib
import re
from datetime import datetime
from typing import Dict, Tuple, Optional, List
from utils import (
    calculate_entropy,
    detect_double_extension,
    detect_unicode_tricks,
    is_potentially_malicious_archive,
    analyze_archive_contents,
    scan_directory,
    get_suspicious_patterns
)
from enhanced_utils import (
    SuspicionScorer,
    EnhancedFileTypeDetector,
    DirectoryScanSummary
)
from report_utils import ReportExporter

try:
    from colorama import init, Fore, Style
    COLORS_ENABLED = True
    init()
except ImportError:
    COLORS_ENABLED = False

def colorize(text: str, color: str) -> str:
    """Add color to text if colors are enabled."""
    if not COLORS_ENABLED:
        return text
        
    color_map = {
        'red': Fore.RED,
        'green': Fore.GREEN,
        'yellow': Fore.YELLOW,
        'blue': Fore.BLUE
    }
    return f"{color_map.get(color, '')}{text}{Style.RESET_ALL}"

class MagicCheck:
    def __init__(self):
        # Dictionary of known file signatures (magic numbers)
        self.signatures = {
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
        
        # Extension to type mapping
        self.extension_map = {
            'jpg': 'JPG/JPEG',
            'jpeg': 'JPG/JPEG',
            'png': 'PNG',
            'gif': 'GIF',
            'pdf': 'PDF',
            'doc': 'DOC/XLS',
            'docx': 'DOCX/XLSX',
            'xls': 'DOC/XLS',
            'xlsx': 'DOCX/XLSX',
            'exe': 'EXE',
            'dll': 'EXE',
            'zip': 'ZIP',
            'rar': 'RAR',
            '7z': '7Z',
            'gz': 'GZIP',
            'tar': 'TAR',
            'elf': 'ELF',
            'py': 'PYTHON',
            'pyc': 'PYTHON-BYTECODE',
            'json': 'JSON',
            'md': 'MARKDOWN',
            'txt': 'TEXT'
        }
        
        # Entropy thresholds
        self.entropy_thresholds = {
            'JPG/JPEG': 7.7,
            'PNG': 7.5,
            'PDF': 7.0,
            'ZIP': 7.8,
            'RAR': 7.8,
            '7Z': 7.8,
            'GZIP': 7.8,
            'default': 7.0
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

    def check_file(self, filepath: str) -> Optional[Dict]:
        """
        Analyze a single file and return results.
        Returns None if the file is not suspicious and should be ignored.
        """
        if not os.path.exists(filepath):
            return None

        # Basic file info
        filename = os.path.basename(filepath)
        try:
            filesize = os.path.getsize(filepath)
        except:
            return None

        # Get actual file type and extension
        magic_bytes = self.read_magic_bytes(filepath)
        if not magic_bytes:
            return None

        actual_type = self.get_file_type(magic_bytes)
        ext = self.get_file_extension(filepath)
        
        # Special file type detection
        if '.git/objects/' in filepath:
            actual_type = 'GIT-OBJECT'
        elif '__pycache__' in filepath and ext == 'pyc':
            actual_type = 'PYTHON-BYTECODE'
        elif ext == 'py':
            actual_type = 'PYTHON'
        elif ext == 'json':
            actual_type = 'JSON'
        elif ext == 'md':
            actual_type = 'MARKDOWN'
        elif ext == 'txt':
            actual_type = 'TEXT'

        # Calculate file hash
        file_hash = self.calculate_hash(filepath)
        if not file_hash:
            return None

        # Known safe paths
        SAFE_PATHS = [
            '.git/objects/',
            '.git/refs/',
            '.git/hooks/',
            '__pycache__/',
            '.pytest_cache/',
            '.git/'
        ]
        
        # Check if file is in a safe path
        is_safe_path = any(safe_path in filepath for safe_path in SAFE_PATHS)
        
        # Check if file has a known safe type
        SAFE_TYPES = {'PYTHON', 'PYTHON-BYTECODE', 'JSON', 'MARKDOWN', 'TEXT', 'GIT-OBJECT'}
        is_safe_type = actual_type in SAFE_TYPES

        # If file is safe, return basic info without deep analysis
        if is_safe_path or is_safe_type:
            return {
                'filepath': filepath,
                'filename': filename,
                'filesize': filesize,
                'actual_type': actual_type,
                'risk_level': 'Safe',
                'sha256': file_hash,
                'reasons': ['Known safe file type or location']
            }

        # For other files, perform deeper analysis
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                entropy = calculate_entropy(data)
        except:
            entropy = 0.0

        # Analyze filename
        filename_analysis = {
            'double_extension': detect_double_extension(filename),
            'unicode_tricks': detect_unicode_tricks(filename),
            'suspicious_patterns': [p for p in get_suspicious_patterns() if re.search(p, filename, re.IGNORECASE)]
        }

        # Check for suspicious indicators
        is_suspicious = False
        reasons = []

        if filename_analysis['double_extension']:
            if any(ext in filename.lower() for ext in ['exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'js']):
                is_suspicious = True
                reasons.append('Executable double extension detected')

        if filename_analysis['unicode_tricks']:
            is_suspicious = True
            reasons.append('Unicode manipulation detected')

        if filename_analysis['suspicious_patterns']:
            is_suspicious = True
            reasons.append('Suspicious filename patterns detected')

        # Check entropy against thresholds
        threshold = self.entropy_thresholds.get(actual_type, self.entropy_thresholds['default'])
        is_high_entropy = entropy > threshold
        
        if is_high_entropy and actual_type not in ['JPG/JPEG', 'PNG', 'ZIP', 'RAR', '7Z', 'GZIP']:
            is_suspicious = True
            reasons.append(f'High entropy ({entropy:.2f} > {threshold})')

        # Check archives
        archive_analysis = None
        if actual_type in ['ZIP', 'RAR']:
            archive_analysis = analyze_archive_contents(filepath)
            if archive_analysis and archive_analysis.get('is_malicious'):
                is_suspicious = True
                reasons.append('Suspicious archive contents')

        # Prepare result
        result = {
            'filepath': filepath,
            'filename': filename,
            'filesize': filesize,
            'actual_type': actual_type,
            'risk_level': 'Suspicious' if is_suspicious else 'Safe',
            'reasons': reasons,
            'sha256': file_hash,
            'entropy': entropy,
            'filename_analysis': filename_analysis
        }

        if archive_analysis:
            result['archive_analysis'] = archive_analysis

        return result

    def scan_directory(self, directory: str) -> List[Dict]:
        """Scan a directory recursively and return analysis results for all files."""
        results = []
        total_files = 0
        safe_files = 0
        suspicious_files = 0

        # First count total files
        all_files = []
        for root, _, files in os.walk(directory):
            for file in files:
                all_files.append(os.path.join(root, file))
        
        total_to_scan = len(all_files)
        print(f"\nFound {total_to_scan} files to scan...\n")
        
        # Now scan each file
        for idx, filepath in enumerate(all_files, 1):
            try:
                result = self.check_file(filepath)
                status = "Safe" if result and result['risk_level'] == 'Safe' else "Suspicious" if result else "Ignored"
                status_color = {
                    "Safe": "green",
                    "Suspicious": "red",
                    "Ignored": "yellow"
                }[status]
                
                print(f"[{idx}/{total_to_scan}] Scanning: {filepath}")
                print(f"Status: {colorize(status, status_color)}")
                
                if result:
                    results.append(result)
                    if result['risk_level'] == 'Safe':
                        safe_files += 1
                        print(colorize("Reason: " + result['reasons'][0], "green"))
                    elif result['risk_level'] == 'Suspicious':
                        suspicious_files += 1
                        # Show reasons for suspicious files
                        if 'reasons' in result:
                            print(colorize("Reasons:", "red"))
                            for reason in result['reasons']:
                                print(colorize(f"- {reason}", "red"))
                total_files += 1
                print()  # Add blank line between files
            except Exception as e:
                print(colorize(f"Error processing {filepath}: {str(e)}", "red"))
                print()

        # Print summary
        print("\nDirectory Scan Summary:")
        print(f"Total Files: {colorize(str(total_files), 'blue')}")
        if safe_files > 0:
            print(f"Safe Files: {colorize(str(safe_files), 'green')} ({safe_files/total_files*100:.1f}%)")
        if suspicious_files > 0:
            print(f"Suspicious Files: {colorize(str(suspicious_files), 'red')} ({suspicious_files/total_files*100:.1f}%)")

        return results

def main():
    print("\nMagicCheck - Advanced File Analysis Tool")
    print("----------------------------------------")
    print("1. Scan single file")
    print("2. Scan directory")
    choice = input("\nChoose scan type (1/2): ").strip()
    
    print("\nChoose report format:")
    print("1. Terminal output only")
    print("2. JSON report")
    print("3. CSV report")
    print("4. HTML report")
    report_choice = input("Select format (1-4): ").strip()

    checker = MagicCheck()
    results = []

    if choice == "1":
        filepath = input("\nEnter file path: ").strip('" ')
        result = checker.check_file(filepath)
        if result:
            results.append(result)
            print("\nAnalysis Results:")
            for key, value in result.items():
                print(f"{key}: {value}")
    elif choice == "2":
        directory = input("\nEnter directory path: ").strip('" ')
        results = checker.scan_directory(directory)
    else:
        print("Invalid choice!")
        return

    if results and report_choice != "1":
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_path = os.path.join(os.getcwd(), f"magiccheck_report_{timestamp}")
        
        if report_choice == "2":
            ReportExporter.to_json(results, base_path + ".json")
            print(f"\nJSON report saved to: {base_path}.json")
        elif report_choice == "3":
            ReportExporter.to_csv(results, base_path + ".csv")
            print(f"\nCSV report saved to: {base_path}.csv")
        elif report_choice == "4":
            ReportExporter.to_html(results, base_path + ".html")
            print(f"\nHTML report saved to: {base_path}.html")

if __name__ == "__main__":
    main()
