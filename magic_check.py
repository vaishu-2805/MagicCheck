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
        try:
            import magic
            self.python_magic = magic
        except ImportError:
            self.python_magic = None
            
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

    def get_file_type(self, magic_bytes: bytes, filepath: str = None) -> str:
        """Determine file type from magic bytes with multiple fallbacks."""
        # Try magic bytes first
        for signature, file_type in self.signatures.items():
            if magic_bytes.startswith(signature):
                return file_type
        
        # Try python-magic if available
        if self.python_magic and filepath:
            try:
                mime_type = self.python_magic.from_file(filepath, mime=True)
                if mime_type:
                    # Convert mime type to our format
                    mime_map = {
                        'text/plain': 'TEXT',
                        'text/markdown': 'MARKDOWN',
                        'text/x-python': 'PYTHON',
                        'application/json': 'JSON',
                        'text/html': 'HTML',
                        'text/xml': 'XML',
                        'application/x-executable': 'EXE',
                        'application/x-dosexec': 'EXE',
                        'application/x-sharedlib': 'DLL'
                    }
                    return mime_map.get(mime_type, mime_type.split('/')[-1].upper())
            except Exception:
                pass
                
        # Finally try mimetypes
        if filepath:
            import mimetypes
            mime_type, _ = mimetypes.guess_type(filepath)
            if mime_type:
                return mime_type.split('/')[-1].upper()
                
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

    def check_archive_anomalies(self, archive_analysis: dict, filepath: str) -> tuple[float, list[str]]:
        """Check for suspicious indicators in archive files."""
        score = 0.0
        reasons = []
        
        # Check for compression ratio anomalies
        if archive_analysis.get('total_size', 0) > 0 and archive_analysis.get('compressed_size', 0) > 0:
            compression_ratio = 1 - (archive_analysis['compressed_size'] / archive_analysis['total_size'])
            
            # Check compression patterns
            if compression_ratio < 0.01:  # Almost no compression
                score += 0.3
                reasons.append(f"Suspicious: Archive has no compression (ratio: {compression_ratio:.2f})")
            elif compression_ratio > 0.95 and archive_analysis.get('total_size', 0) > 1000:
                # Unusually high compression for a large file
                score += 0.3
                reasons.append(f"Suspicious: Abnormally high compression ratio ({compression_ratio:.2f})")
                
        # Check for unusually small files
        if archive_analysis.get('total_size', 0) < 150:  # Suspiciously small
            score += 0.2
            reasons.append("Suspicious: Archive contents are unusually small")
            
        # Check archive structure
        if archive_analysis.get('nested_archives', []):
            score += 0.2
            reasons.append("Suspicious: Contains nested archives")
            
        if archive_analysis.get('path_traversal_attempts', []):
            score += 0.4
            reasons.append("Suspicious: Potential path traversal in filenames")
            
        # Check for suspicious file combinations
        file_types = archive_analysis.get('file_types', {})
        if '.exe' in file_types and any(ext in file_types for ext in ['.doc', '.xls', '.pdf', '.txt']):
            score += 0.3
            reasons.append("Suspicious: Archive contains both executables and documents")
            
        # Enhanced image file checks
        for ext, count in file_types.items():
            if ext.lower() in ['.jpg', '.jpeg', '.png', '.gif']:
                min_expected_size = 500  # Most real images are larger
                if archive_analysis.get('total_size', 0) < min_expected_size:
                    score += 0.3
                    reasons.append(f"Suspicious: Image file in archive is too small ({archive_analysis['total_size']} bytes)")
                    
                # Check for impossible image dimensions
                try:
                    with open(filepath, 'rb') as f:
                        header = f.read(24)  # Read enough for image headers
                        if ext.lower() in ['.png']:
                            # Check PNG dimensions (bytes 16-24)
                            width = int.from_bytes(header[16:20], 'big')
                            height = int.from_bytes(header[20:24], 'big')
                            if width * height * 3 > archive_analysis['total_size']:  # Impossible dimensions
                                score += 0.4
                                reasons.append(f"Suspicious: Image dimensions impossible for file size")
                except:
                    pass
        
        # Check for impossible content sizes
        total_claimed = sum(
            size * count for (ext, count), size in [
                (('.jpg', 1), 200000),  # Minimum realistic sizes
                (('.png', 1), 100000),
                (('.pdf', 1), 20000),
                (('.doc', 1), 50000),
                (('.exe', 1), 20000)
            ] if ext in file_types
        )
        if total_claimed > archive_analysis.get('total_size', 0) * 5:  # Even with compression
            score += 0.3
            reasons.append("Suspicious: Claimed content sizes impossible for archive size")
            
        # Check for format-specific anomalies
        if archive_analysis.get('compression_anomalies', []):
            score += 0.3
            reasons.extend([f"Suspicious: {anomaly}" for anomaly in archive_analysis['compression_anomalies']])
            
        return score, reasons
        
    def check_binary_anomalies(self, data: bytes, file_type: str) -> tuple[float, list[str]]:
        """Check for suspicious patterns in binary content."""
        score = 0.0
        reasons = []
        
        # Check for encrypted/encoded content
        try:
            # Check for base64-encoded data
            b64_pattern = rb'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
            if len(re.findall(b64_pattern, data)) > len(data) / 100:  # Significant base64 content
                score += 0.2
                reasons.append("Contains probable base64-encoded data")
                
            # Check for encrypted/packed code indicators
            if b'This program cannot be run in DOS mode' in data and b'UPX' in data:
                score += 0.3
                reasons.append("Contains packed executable code")
                
            # Check for script content in binary files
            if file_type not in ['TEXT', 'PYTHON', 'HTML']:
                script_patterns = [rb'<script', rb'function.*\(.*\)', rb'eval\(', rb'exec\(']
                for pattern in script_patterns:
                    if re.search(pattern, data):
                        score += 0.3
                        reasons.append("Contains embedded script code")
                        break
        except:
            pass
            
        # Look for known malicious patterns
        mal_patterns = [
            (rb'powershell.*bypass', "PowerShell bypass attempt"),
            (rb'cmd.exe.*\/c', "Command shell execution"),
            (rb'rundll32\.exe', "Suspicious rundll32 usage"),
            (rb'reg.*delete', "Registry manipulation"),
            (rb'net.*localgroup.*administrators', "Admin group manipulation"),
            (rb'CreateRemoteThread', "Potential process injection"),
        ]
        
        for pattern, reason in mal_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                score += 0.4
                reasons.append(f"Suspicious: {reason}")
                
        return score, reasons
        
    def check_image_steganography(self, data: bytes, file_type: str) -> tuple[bool, str]:
        """Check for steganography indicators in image files."""
        if file_type not in ['PNG', 'JPG/JPEG', 'GIF']:
            return False, ""
            
        # Check for data after image end markers
        if file_type == 'PNG' and b'IEND' in data:
            iend_pos = data.find(b'IEND') + 8  # IEND chunk is 4 bytes + 4 byte CRC
            if iend_pos < len(data):
                return True, "Hidden data found after PNG end marker"
                
        if file_type == 'JPG/JPEG' and b'\xff\xd9' in data:
            end_pos = data.find(b'\xff\xd9') + 2
            if end_pos < len(data):
                return True, "Hidden data found after JPEG end marker"

        # Check for abnormal data patterns and LSB analysis
        try:
            # Sample the first 1000 bytes for LSB analysis
            sample = data[:1000]
            lsb_count = sum(bin(b).count('1') for b in sample)
            avg_lsb = lsb_count / len(sample)
            
            # Normal images typically have more balanced LSBs
            if avg_lsb > 0.9 or avg_lsb < 0.1:
                return True, "Unusual LSB pattern detected (possible steganography)"
                
            # Check for unusual entropy in color channels
            if len(data) > 100:
                chunks = [data[i:i+3] for i in range(0, min(len(data), 3000), 3)]
                channel_entropies = []
                
                for channel in range(3):  # RGB channels
                    channel_data = bytes([chunk[channel] for chunk in chunks if len(chunk) > channel])
                    channel_entropy = calculate_entropy(channel_data)
                    channel_entropies.append(channel_entropy)
                
                # Check for significant entropy differences between channels
                avg_entropy = sum(channel_entropies) / 3
                max_diff = max(abs(e - avg_entropy) for e in channel_entropies)
                
                if max_diff > 1.0:  # Significant entropy difference between channels
                    return True, "Unusual color channel entropy detected (possible steganography)"
            
        except Exception:
            pass
            
        return False, ""

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
            
        # Handle git files first to avoid unnecessary processing
        if '.git/' in filepath:
            file_hash = self.calculate_hash(filepath)
            if not file_hash:
                return None
            return {
                'filepath': filepath,
                'filename': filename,
                'filesize': filesize,
                'actual_type': 'GIT-OBJECT',
                'risk_level': 'Safe',
                'sha256': file_hash,
                'reasons': ['Git repository data files']
            }

        # Get actual file type and extension
        magic_bytes = self.read_magic_bytes(filepath)
        if not magic_bytes:
            return None

        actual_type = self.get_file_type(magic_bytes)
        ext = self.get_file_extension(filepath)
        
        # Special file type detection
        # Handle git files
        if '.git/' in filepath:
            actual_type = 'GIT-OBJECT'
            return {
                'filepath': filepath,
                'filename': filename,
                'filesize': filesize,
                'actual_type': actual_type,
                'risk_level': 'Safe',
                'sha256': file_hash,
                'reasons': ['Git repository data files']
            }
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

        # Check for suspicious indicators using a weighted scoring system
        suspicion_score = 0.0
        reasons = []
        
        # Content-based checks (weighted more heavily)
        
        # Check for steganography in images
        if actual_type in ['PNG', 'JPG/JPEG', 'GIF']:
            try:
                with open(filepath, 'rb') as f:
                    file_data = f.read()
                has_stego, stego_reason = self.check_image_steganography(file_data, actual_type)
                if has_stego:
                    suspicion_score += 0.6  # High weight for steganography
                    reasons.append(stego_reason)
            except Exception as e:
                print(f"Error checking steganography: {e}")
        
        # Check entropy against thresholds
        threshold = self.entropy_thresholds.get(actual_type, self.entropy_thresholds['default'])
        
        # For archives, also check for suspiciously LOW entropy
        if actual_type in ['ZIP', 'RAR', '7Z', 'GZIP']:
            if entropy < 5.0:  # Suspiciously low for a compressed format
                suspicion_score += 0.3
                reasons.append(f'Suspiciously low entropy for compressed format ({entropy:.2f} < 5.0)')
        else:
            # For non-archives, check for high entropy
            is_high_entropy = entropy > threshold
            if is_high_entropy and actual_type not in ['JPG/JPEG', 'PNG']:
                suspicion_score += 0.4
                reasons.append(f'High entropy ({entropy:.2f} > {threshold})')

        # Enhanced archive analysis
        archive_analysis = None
        if actual_type in ['ZIP', 'RAR']:
            archive_analysis = analyze_archive_contents(filepath)
            if archive_analysis:
                if archive_analysis.get('is_malicious'):
                    suspicion_score += 0.5
                    reasons.append('Suspicious archive contents')
                
                # Check for archive anomalies
                anomaly_score, anomaly_reasons = self.check_archive_anomalies(archive_analysis, filepath)
                suspicion_score += anomaly_score
                reasons.extend(anomaly_reasons)
                
        # Check for binary anomalies in file content
        try:
            with open(filepath, 'rb') as f:
                file_data = f.read()
                binary_score, binary_reasons = self.check_binary_anomalies(file_data, actual_type)
                suspicion_score += binary_score
                reasons.extend(binary_reasons)
        except Exception as e:
            print(f"Error checking binary content: {e}")
            
        # Calculate final risk score (0-100)
        risk_score = min(int(suspicion_score * 100), 100)
        
        # Determine risk level based on score
        if risk_score < 20:
            risk_level = 'Safe'
            risk_label = f'LOW RISK ({risk_score}/100)'
        elif risk_score < 50:
            risk_level = 'Warning'
            risk_label = f'MEDIUM RISK ({risk_score}/100)'
        else:
            risk_level = 'Dangerous'
            risk_label = f'HIGH RISK ({risk_score}/100)'
            
        # Try to get VirusTotal info if available
        vt_info = None
        try:
            import requests
            VT_API_KEY = os.getenv('VT_API_KEY')
            if VT_API_KEY and file_hash:
                headers = {'x-apikey': VT_API_KEY}
                response = requests.get(f'https://www.virustotal.com/vtapi/v2/file/report?apikey={VT_API_KEY}&resource={file_hash}')
                if response.status_code == 200:
                    result = response.json()
                    if result.get('response_code') == 1:
                        positives = result.get('positives', 0)
                        total = result.get('total', 0)
                        if positives > 0:
                            vt_info = f"VirusTotal: {positives}/{total} detections (Malicious)"
                            suspicion_score += 0.5
                            reasons.append(vt_info)
        except:
            pass
        
        # Check file type mismatch (moderate weight)
        declared_type = self.extension_map.get(ext, 'Unknown').upper()
        if actual_type != "Unknown" and declared_type != "Unknown" and actual_type != declared_type:
            suspicion_score += 0.3
            reasons.append(f'File type mismatch: Declared as {declared_type}, actually {actual_type}')
        
        # Filename-based checks (weighted less)
        if filename_analysis['double_extension']:
            if any(ext in filename.lower() for ext in ['exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'js']):
                suspicion_score += 0.3
                reasons.append('Executable double extension detected')

        if filename_analysis['unicode_tricks']:
            suspicion_score += 0.2
            reasons.append('Unicode manipulation detected')

        if filename_analysis['suspicious_patterns']:
            # Only small contribution from suspicious patterns
            suspicion_score += 0.1
            reasons.append('Suspicious filename patterns detected')

        # Determine if file is suspicious based on cumulative score
        # A score of 0.5 or higher indicates enough suspicious elements
        is_suspicious = suspicion_score >= 0.5

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

    def scan_directory(self, directory: str, report_choice: str = "1") -> List[Dict]:
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

        # Format and print scan summary
        reports = []
        if report_choice == "2":
            reports.append("JSON")
        elif report_choice == "3":
            reports.append("CSV")
        elif report_choice == "4":
            reports.append("HTML")
            
        summary = format_scan_summary(
            total_files=total_files,
            safe_files=f"{safe_files} ({(safe_files/total_files*100):.1f}%)" if total_files > 0 else "0",
            suspicious_files=f"{suspicious_files} ({(suspicious_files/total_files*100):.1f}%)" if total_files > 0 else "0",
            ignored_files=f"{total_files - (safe_files + suspicious_files)} ({((total_files - (safe_files + suspicious_files))/total_files*100):.1f}%)" if total_files > 0 else "0",
            reports_saved=", ".join(reports) if reports else None
        )
        
        # Color the summary based on results
        if suspicious_files > 0:
            print(colorize(summary, 'red'))
        elif total_files - (safe_files + suspicious_files) > 0:
            print(colorize(summary, 'yellow'))
        else:
            print(colorize(summary, 'green'))

        return results

def print_fancy_header():
    """Print a fancy colorized header."""
    header = """
╔═══════════════════════════════════════╗
║     MagicCheck - Security Scanner     ║
║      Advanced File Analysis Tool      ║
╚═══════════════════════════════════════╝
"""
    print(colorize(header, 'blue'))

def format_scan_summary(total_files, safe_files, suspicious_files, ignored_files, reports_saved=None):
    """Format a nice summary table."""
    summary = f"""
┌{'═' * 30}┐
│ Directory Scan Summary {' ' * 7}│
├{'─' * 30}┤
│ Total Files Scanned: {str(total_files).ljust(8)} │
│ Safe Files: {str(safe_files).ljust(17)} │
│ Suspicious Files: {str(suspicious_files).ljust(12)} │
│ Ignored Files: {str(ignored_files).ljust(14)} │
"""
    if reports_saved:
        summary += f"│ Reports Saved: {reports_saved.ljust(14)} │\n"
    summary += f"└{'═' * 30}┘"
    return summary

def main():
    print_fancy_header()
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
