#!/usr/bin/env python3

import os
import struct
import hashlib
import re
from datetime import datetime
from typing import Dict, Tuple, Optional, List
from collections import defaultdict
from utils import (
    calculate_entropy,
    detect_double_extension,
    detect_unicode_tricks,
    is_potentially_malicious_archive,
    analyze_archive_contents,
    scan_directory,
    get_suspicious_patterns,
    SuspicionScorer,
    EnhancedFileTypeDetector,
    DirectoryScanSummary,
    ReportExporter
)

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
            
        # Enhanced dictionary of known file signatures (magic numbers)
        self.signatures = {
            # Images
            b'\xFF\xD8\xFF': 'JPG/JPEG',  # JPEG/JFIF
            b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': 'PNG',  # PNG
            b'\x47\x49\x46\x38': 'GIF',  # GIF87a/GIF89a
            b'\x42\x4D': 'BMP',  # BMP
            b'\x00\x00\x01\x00': 'ICO',  # ICO
            
            # Executables
            b'\x4D\x5A': 'EXE',  # DOS MZ executable
            b'\x7F\x45\x4C\x46': 'ELF',  # ELF
            b'\xCA\xFE\xBA\xBE': 'MACHO',  # Mach-O binary
            b'\x4D\x53\x43\x46': 'CAB',  # Microsoft cabinet file
            b'\x50\x45\x00\x00': 'PE',  # PE (exe/dll/sys)
            
            # Archives
            b'\x50\x4B\x03\x04': 'ZIP',  # ZIP
            b'\x52\x61\x72\x21\x1A\x07': 'RAR',  # RAR
            b'\x37\x7A\xBC\xAF\x27\x1C': '7Z',  # 7-Zip
            b'\x1F\x8B\x08': 'GZIP',  # GZIP
            b'\x42\x5A\x68': 'BZIP2',  # BZIP2
            b'\x75\x73\x74\x61\x72': 'TAR',  # TAR
            
            # Documents
            b'\x25\x50\x44\x46': 'PDF',  # PDF
            b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': 'MS_COMPOUND',  # MS Compound (doc/xls)
            b'\x50\x4B\x03\x04\x14\x00\x06\x00': 'OFFICE_OPEN_XML',  # DOCX/XLSX/PPTX
            b'%!PS': 'PS',  # PostScript
            
            # Scripts
            b'\x23\x21': 'SCRIPT',  # Shebang (#!)
            b'\x40\x65\x63\x68\x6F\x20\x6F\x66\x66': 'BAT',  # Batch file
            b'\x72\x65\x67\x66': 'REG',  # Registry file
            
            # Media
            b'\x00\x00\x00\x14\x66\x74\x79\x70': 'MP4',  # MP4
            b'\x49\x44\x33': 'MP3',  # MP3 with ID3
            b'\x52\x49\x46\x46': 'AVI/WAV',  # RIFF (AVI/WAV)
        }
        
        # High-risk file types that need special attention
        self.high_risk_types = {
            'EXE', 'PE', 'DLL', 'SCR', 'BAT', 'CMD', 'PS1', 'VBS', 'JS', 'WSF', 'MSI',
            'REG', 'SCRIPT', 'MACHO', 'ELF'
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
            'PDF': 7.9,        # PDFs naturally have high entropy due to compression
            'ZIP': 7.8,
            'RAR': 7.8,
            '7Z': 7.8,
            'GZIP': 7.8,
            'DOCX/XLSX': 7.5,  # Office files can have high entropy
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

    def analyze_archive_file(self, file_data: bytes, filename: str) -> tuple[float, list[str]]:
        """Analyze individual file within an archive."""
        score = 0.0
        reasons = []
        
        # Check file entropy
        entropy = calculate_entropy(file_data)
        if entropy > 7.5:
            score += 0.3
            reasons.append(f"High entropy ({entropy:.2f}) suggests encryption/packing")
            
        # Check magic bytes vs extension
        ext = os.path.splitext(filename)[1].lower()
        magic_bytes = file_data[:8]
        declared_type = self.extension_map.get(ext.lstrip('.'), 'Unknown').upper()
        actual_type = self.get_file_type(magic_bytes)
        
        if actual_type != "Unknown" and declared_type != "Unknown" and actual_type != declared_type:
            score += 0.4
            reasons.append(f"Type mismatch: Claims {declared_type}, actually {actual_type}")
            
        # Check for suspicious patterns in content
        patterns = {
            b'powershell': ('PowerShell script detected', 0.4),
            b'cmd.exe': ('Command shell reference found', 0.3),
            b'rundll32': ('RunDLL32 reference found', 0.3),
            b'CreateRemoteThread': ('Potential process injection', 0.5)
        }
        
        for pattern, (reason, pattern_score) in patterns.items():
            if pattern in file_data:
                score += pattern_score
                reasons.append(reason)
                
        return score, reasons

    def check_archive_anomalies(self, archive_analysis: dict, filepath: str) -> tuple[float, list[str]]:
        """Check for suspicious indicators in archive files."""
        score = 0.0
        reasons = []

        # Get basic archive info
        total_size = archive_analysis.get('total_size', 0)
        compressed_size = archive_analysis.get('compressed_size', 0)
        files = archive_analysis.get('files', {})
        file_types = defaultdict(int)
        nested_depth = 0
        max_size = 0
        total_files = 0
        executable_count = 0
        script_count = 0
        hidden_count = 0

        # Analyze each file in archive
        for filename, info in files.items():
            if any(pattern in filename.lower() for pattern in ['__macos', '.ds_store']):
                continue  # Skip OS metadata files

            total_files += 1
            file_size = info.get('size', 0)
            ext = os.path.splitext(filename)[1].lower()
            file_types[ext] += 1
            max_size = max(max_size, file_size)

            # Track nesting depth
            depth = filename.count('/') + filename.count('\\')
            nested_depth = max(nested_depth, depth)

            # Check for hidden files
            if filename.startswith('.'):
                hidden_count += 1

            # Check for executables and scripts
            if ext in ['.exe', '.dll', '.sys', '.msi']:
                executable_count += 1
                if file_size < 10000:  # Tiny executables are suspicious
                    score += 0.4
                    reasons.append(f"Suspicious: Very small executable {filename} ({file_size} bytes)")

            if ext in ['.vbs', '.bat', '.ps1', '.js', '.hta', '.wsf']:
                script_count += 1
                if file_size < 100:  # Tiny scripts are suspicious
                    score += 0.4
                    reasons.append(f"Suspicious: Very small script {filename} ({file_size} bytes)")

            # Check file type mismatches using content magic bytes
            if info.get('content'):
                content_score, content_reasons = self.analyze_archive_file(info['content'], filename)
                score += content_score
                reasons.extend(content_reasons)

        # Check compression ratio patterns
        if total_size > 0 and compressed_size > 0:
            compression_ratio = 1 - (compressed_size / total_size)

            # Analyze different ratio scenarios
            if compression_ratio < 0.01:  # Almost no compression
                if total_size > 10000:  # Large files should compress somewhat
                    score += 0.4
                    reasons.append(f"Suspicious: Large archive has no compression (ratio: {compression_ratio:.2f})")
                else:
                    score += 0.2
                    reasons.append(f"Low compression ratio ({compression_ratio:.2f})")

            elif compression_ratio > 0.95:
                if total_size > 1000:  # Unusually high compression for large files
                    score += 0.4
                    reasons.append(f"Suspicious: Abnormally high compression ratio ({compression_ratio:.2f})")
                else:
                    score += 0.2
                    reasons.append(f"Very high compression ratio ({compression_ratio:.2f})")

            # Check for compression ratio inconsistencies
            if max_size > 0:
                expected_ratio = min(0.8, max_size / total_size)  # Larger files should compress better
                if compression_ratio < expected_ratio * 0.5:  # Much worse than expected
                    score += 0.3
                    reasons.append("Compression ratio much lower than expected")

        # Check archive structure patterns
        if nested_depth > 5:
            score += 0.2
            reasons.append(f"Deeply nested archive structure (depth: {nested_depth})")

        if total_files == 1 and max_size < 50000:
            score += 0.3
            reasons.append(f"Single small file ({max_size} bytes) in archive (possible obfuscation)")

        if hidden_count > total_files * 0.3:  # More than 30% hidden files
            score += 0.3
            reasons.append(f"High proportion of hidden files ({hidden_count}/{total_files})")

        # Check file type diversity and combinations
        unique_types = len(file_types)
        if unique_types > 10:
            score += 0.2
            reasons.append(f"Unusually diverse file types ({unique_types} different types)")

        # Check suspicious combinations
        if executable_count > 0:
            if script_count > 0:
                score += 0.5
                reasons.append("Contains both executables and scripts (high risk)")
            if any(ext in file_types for ext in ['.doc', '.xls', '.pdf']):
                score += 0.4
                reasons.append("Contains both executables and documents (suspicious)")

        # Check for hidden archives
        if archive_analysis.get('nested_archives', []):
            nested_info = archive_analysis['nested_archives']
            if isinstance(nested_info, list) and len(nested_info) > 0:
                score += 0.3
                reasons.append(f"Contains {len(nested_info)} nested archives")

        # Check for path traversal attempts
        if archive_analysis.get('path_traversal_attempts', []):
            traversal_info = archive_analysis['path_traversal_attempts']
            if isinstance(traversal_info, list) and len(traversal_info) > 0:
                score += 0.5
                reasons.append(f"Found {len(traversal_info)} path traversal attempts")

        # Enhanced image file analysis
        for ext, count in file_types.items():
            if ext in ['.jpg', '.jpeg', '.png', '.gif']:
                # Check for common image sizes
                if max_size < 500:  # Extremely small for a real image
                    score += 0.3
                    reasons.append(f"Suspiciously small image files (max {max_size} bytes)")

                # Check PNG dimensions if available
                if ext == '.png' and 'content' in files:
                    try:
                        content = files['content']
                        if len(content) >= 24:
                            width = int.from_bytes(content[16:20], 'big')
                            height = int.from_bytes(content[20:24], 'big')
                            expected_min = width * height * 3 // 100  # Very conservative minimum
                            if total_size < expected_min:
                                score += 0.4
                                reasons.append(f"Image dimensions impossible for file size")
                    except:
                        pass

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
            # Check for base64-encoded data with improved accuracy
            try:
                b64_pattern = rb'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
                matches = re.findall(b64_pattern, data)
                total_b64_len = sum(len(m) for m in matches)
                
                # Only flag if there's a significant amount of base64 data
                if matches and total_b64_len > 1000 and total_b64_len > len(data) / 10:
                    # Try to decode a sample to verify it's actually base64
                    try:
                        import base64
                        sample = matches[0]  # We know matches has at least one item
                        base64.b64decode(sample)
                        # Only report if we can successfully decode
                        score += 0.2
                        reasons.append("Contains verified base64-encoded data")
                    except (IndexError, base64.binascii.Error):
                        pass  # Not valid base64, don't report
            except Exception:
                pass  # Any other error, skip base64 detection
                
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
        
    def extract_hidden_payload(self, data: bytes, start_pos: int, filepath: str) -> tuple[str, bytes, float]:
        """Extract and analyze hidden payload after EOF."""
        hidden_data = data[start_pos:]
        if not hidden_data:
            return "Unknown", b"", 0.0
            
        # Check for common file signatures in hidden data
        signatures = {
            b'PK\x03\x04': ('ZIP', 0.8),
            b'MZ': ('EXE', 0.9),
            b'\x7fELF': ('ELF', 0.9),
            b'Rar!': ('RAR', 0.8),
            b'\x89PNG': ('PNG', 0.7),
            b'\xFF\xD8\xFF': ('JPG', 0.7),
            b'%PDF': ('PDF', 0.7)
        }
        
        # Try to identify the hidden content
        for sig, (ftype, risk) in signatures.items():
            if hidden_data.startswith(sig):
                # Save extracted payload
                output_dir = "extracted_payloads"
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir)
                    
                basename = os.path.splitext(os.path.basename(filepath))[0]
                output_path = os.path.join(output_dir, f"{basename}_hidden.{ftype.lower()}")
                with open(output_path, 'wb') as f:
                    f.write(hidden_data)
                return f"{ftype} (saved to {output_path})", hidden_data, risk
        
        # Check for base64 encoded data
        try:
            import base64
            # Try to decode a sample
            sample = hidden_data[:1000] if len(hidden_data) > 1000 else hidden_data
            decoded = base64.b64decode(sample)
            return "Base64 Encoded Data", hidden_data, 0.6
        except:
            pass
            
        # Check for encrypted/compressed data using entropy
        entropy = calculate_entropy(hidden_data)
        if entropy > 7.0:
            return "Encrypted/Compressed Data", hidden_data, 0.7
            
        return "Unknown Binary Data", hidden_data, 0.5

    def check_image_steganography(self, data: bytes, file_type: str) -> tuple[bool, str]:
        """Check for steganography indicators in images."""
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
            # More sophisticated LSB analysis
            # Sample multiple parts of the file
            samples = []
            sample_size = 1000
            
            # Take samples from start, middle, and end
            if len(data) > sample_size * 3:
                samples.append(data[:sample_size])
                samples.append(data[len(data)//2:len(data)//2 + sample_size])
                samples.append(data[-sample_size:])
            else:
                samples.append(data)
            
            suspicious_sections = 0
            for sample in samples:
                lsb_counts = [0, 0]  # Count of 0s and 1s in LSBs
                for byte in sample:
                    lsb = byte & 1
                    lsb_counts[lsb] += 1
                    
                total = sum(lsb_counts)
                if total > 0:
                    ratio = max(lsb_counts) / total
                    if ratio > 0.95 or ratio < 0.05:  # Highly unbalanced LSBs
                        suspicious_sections += 1
            
            # Only report if multiple sections are suspicious
            if suspicious_sections >= 2:
                return True, "Confirmed LSB pattern anomaly (high probability of steganography)"
                
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
        # Initialize result variables
        entropy = 0.0
        file_data = None
        reasons = []
        suspicion_score = 0.0

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
            # Specifically identify Git objects which are naturally high-entropy
            if '/objects/' in filepath and len(os.path.basename(filepath)) == 40:
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
                    'reasons': ['Git object (naturally high entropy)']
                }
            # Handle other Git files
            file_hash = self.calculate_hash(filepath)
            if not file_hash:
                return None
            return {
                'filepath': filepath,
                'filename': filename,
                'filesize': filesize,
                'actual_type': 'GIT-FILE',
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

        # Known safe paths and patterns
        SAFE_PATHS = [
            '.git/objects/',
            '.git/refs/',
            '.git/hooks/',
            '__pycache__/',
            '.pytest_cache/',
            '.git/'
        ]
        
        # Common legitimate file patterns
        COMMON_DOC_PATTERNS = [
            r'resume\.?(doc|docx|pdf)$',
            r'cv\.?(doc|docx|pdf)$',
            r'report\.?(doc|docx|pdf)$',
            r'thesis\.?(doc|docx|pdf)$',
            r'assignment\.?(doc|docx|pdf)$',
            r'agreement\.?(doc|docx|pdf)$',
            r'certificate\.?(doc|docx|pdf)$'
        ]
        
        # Check if file is in a safe path
        is_safe_path = any(safe_path in filepath for safe_path in SAFE_PATHS)
        
        # Check if file has a known safe type
        SAFE_TYPES = {'PYTHON', 'PYTHON-BYTECODE', 'JSON', 'MARKDOWN', 'TEXT', 'GIT-OBJECT'}
        is_safe_type = actual_type in SAFE_TYPES
        
        # Check if file matches common document patterns
        is_common_doc = any(re.search(pattern, filename.lower()) for pattern in COMMON_DOC_PATTERNS) \
                       and not any(sus_pattern in filename.lower() 
                                 for sus_pattern in ['exploit', 'payload', 'malware', 'backdoor'])

        # If file is safe or a common document type, return basic info without deep analysis
        if is_safe_path or is_safe_type or (is_common_doc and entropy < 7.8):
            return {
                'filepath': filepath,
                'filename': filename,
                'filesize': filesize,
                'actual_type': actual_type,
                'risk_level': 'Safe',
                'sha256': file_hash,
                'reasons': ['Known safe file type or location']
            }

        # Initialize entropy to a default value
        entropy = 0.0
        file_data = None
        
        # For other files, perform deeper analysis
        try:
            with open(filepath, 'rb') as f:
                file_data = f.read()
                entropy = calculate_entropy(file_data)
        except Exception as e:
            print(f"Warning: Could not read file content: {str(e)}")
            # Keep going with default entropy value
        
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
        
        # Enhanced image file analysis
        if actual_type in ['PNG', 'JPG/JPEG', 'GIF']:
            try:
                with open(filepath, 'rb') as f:
                    file_data = f.read()
                
                # Basic size check
                if filesize < 100:  # Extremely small for any valid image
                    suspicion_score += 0.3
                    reasons.append(f"Suspiciously small image file ({filesize} bytes)")
                
                # Image format specific checks
                if actual_type == 'PNG':
                    if len(file_data) >= 24:  # PNG header + IHDR chunk
                        # Validate PNG signature
                        if not file_data.startswith(b'\x89PNG\r\n\x1a\n'):
                            suspicion_score += 0.4
                            reasons.append("Invalid PNG header")
                        
                        # Check dimensions
                        width = int.from_bytes(file_data[16:20], 'big')
                        height = int.from_bytes(file_data[20:24], 'big')
                        
                        if width == 0 or height == 0:
                            suspicion_score += 0.5
                            reasons.append("Invalid image dimensions (zero width/height)")
                        elif width * height > filesize * 2:  # Conservative estimate
                            suspicion_score += 0.4
                            reasons.append("Image dimensions too large for file size")
                
                elif actual_type == 'JPG/JPEG':
                    # Check for valid JPEG markers
                    if not (file_data.startswith(b'\xFF\xD8') and file_data.endswith(b'\xFF\xD9')):
                        suspicion_score += 0.3
                        reasons.append("Missing JPEG start/end markers")
                
                # Check for hidden data and steganography
                has_stego, stego_reason = self.check_image_steganography(file_data, actual_type)
                if has_stego:
                    suspicion_score += 0.6  # High weight for steganography
                    reasons.append(stego_reason)
                    
                # Check color channel entropy
                if len(file_data) > 100:
                    chunks = [file_data[i:i+3] for i in range(0, min(len(file_data), 3000), 3)]
                    if len(chunks) > 0:
                        channel_entropies = []
                        for channel in range(3):  # RGB channels
                            channel_data = bytes([chunk[channel] for chunk in chunks if len(chunk) > channel])
                            if channel_data:
                                channel_entropy = calculate_entropy(channel_data)
                                channel_entropies.append(channel_entropy)
                        
                        if len(channel_entropies) == 3:
                            avg_entropy = sum(channel_entropies) / 3
                            max_diff = max(abs(e - avg_entropy) for e in channel_entropies)
                            
                            if max_diff > 1.5:  # Significant entropy difference between channels
                                suspicion_score += 0.4
                                reasons.append(f"Suspicious color channel entropy variance: {max_diff:.2f}")
                                
                # Content-aware size checks based on dimensions and format
                expected_min_size = 0
                if actual_type == 'PNG':
                    expected_min_size = max(500, (width * height * 3) // 100)  # Very conservative estimate
                elif actual_type == 'JPG/JPEG':
                    expected_min_size = 500  # Minimum size for a valid JPEG
                elif actual_type == 'GIF':
                    expected_min_size = 100  # Minimum size for a valid GIF
                    
                if filesize < expected_min_size:
                    suspicion_score += 0.3
                    reasons.append(f"File size ({filesize} bytes) smaller than minimum expected ({expected_min_size} bytes)")
                    
            except Exception as e:
                print(f"Error analyzing image file: {str(e)}")
        
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
                
        # Check for binary anomalies in file content if we have the data
        if file_data:  # Using the file_data we already read
            try:
                binary_score, binary_reasons = self.check_binary_anomalies(file_data, actual_type)
                suspicion_score += binary_score
                reasons.extend(binary_reasons)
            except Exception as e:
                print(f"Warning: Error during binary analysis: {str(e)}")
                # Continue with other checks
            
        # Calculate final risk score (0-100) with context-aware thresholds
        risk_score = min(int(suspicion_score * 100), 100)
        
        # Determine risk level based on context
        if actual_type in self.high_risk_types:
            # Stricter thresholds for high-risk file types
            if risk_score < 10:
                risk_level = 'Safe'
                risk_label = f'LOW RISK ({risk_score}/100)'
            elif risk_score < 30:
                risk_level = 'Warning'
                risk_label = f'MEDIUM RISK ({risk_score}/100)'
            else:
                risk_level = 'Dangerous'
                risk_label = f'HIGH RISK ({risk_score}/100)'
        else:
            # More lenient thresholds for normal files
            if risk_score < 30:
                risk_level = 'Safe'
                risk_label = f'LOW RISK ({risk_score}/100)'
            elif risk_score < 60:
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
        
        # Enhanced file type mismatch detection
        declared_type = self.extension_map.get(ext, 'Unknown').upper()
        
        # Detect attempts to hide dangerous files
        if actual_type in self.high_risk_types:
            if declared_type not in self.high_risk_types:
                # Dangerous file masquerading as harmless type
                suspicion_score += 0.8
                reasons.append(f'ALERT: Dangerous {actual_type} file disguised as {declared_type}!')
                
            # Check for double extensions
            if '.' in os.path.splitext(filename)[0]:
                suspicion_score += 0.9
                reasons.append('ALERT: Double extension detected - possible malware masquerading!')
                
        # Handle normal type mismatches
        elif actual_type != "Unknown" and declared_type != "Unknown" and actual_type != declared_type:
            # Handle special cases
            if (declared_type == 'DOCX/XLSX' and actual_type == 'ZIP') or \
               (declared_type == 'OFFICE_OPEN_XML' and actual_type == 'ZIP'):
                # Modern Office files are ZIP-based, not suspicious
                pass
            else:
                # Regular file type mismatch
                suspicion_score += 0.4
                reasons.append(f'Type mismatch: File claims to be {declared_type}, but is actually {actual_type}')
        
        # Filename-based checks (weighted less)
        if filename_analysis['double_extension']:
            if any(ext in filename.lower() for ext in ['exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'js']):
                suspicion_score += 0.3
                reasons.append('Executable double extension detected')

        if filename_analysis['unicode_tricks']:
            suspicion_score += 0.2
            reasons.append('Unicode manipulation detected')

        if filename_analysis['suspicious_patterns']:
            # Only flag filename patterns if they indicate actual security threats
            high_risk_patterns = {
                r'\.exe\.[^.]+$',
                r'\.(exe|bat|cmd|ps1|vbs|js|wsf|msi|scr)\.',
                r'[<>|&;$()]',
                r'\\\\+[^\\]',
                r'\.\.|~\$'
            }
            
            serious_threats = [p for p in filename_analysis['suspicious_patterns'] 
                             if any(re.search(risk, p) for risk in high_risk_patterns)]
            
            if serious_threats:
                suspicion_score += 0.3
                reasons.append('High-risk filename pattern detected: possible malware/exploit attempt')
            elif any('exploit' in p or 'payload' in p or 'malware' in p 
                    for p in filename_analysis['suspicious_patterns']):
                suspicion_score += 0.2
                reasons.append('Filename suggests malicious content')

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
        processed_files = 0  # Files we actually processed
        safe_files = 0
        suspicious_files = 0
        ignored_files = 0    # Files we skipped

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
                    processed_files += 1
                    if result['risk_level'] == 'Safe':
                        safe_files += 1
                        if result.get('reasons'):
                            print(colorize("Reason: " + result['reasons'][0], "green"))
                    elif result['risk_level'] == 'Suspicious':
                        suspicious_files += 1
                        # Show reasons for suspicious files
                        if result.get('reasons'):
                            print(colorize("Reasons:", "red"))
                            for reason in result['reasons']:
                                print(colorize(f"- {reason}", "red"))
                else:
                    ignored_files += 1
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
            
        total_processed = processed_files + ignored_files
        summary = format_scan_summary(
            total_files=total_processed,
            safe_files=f"{safe_files} ({(safe_files/total_processed*100):.1f}%)" if total_processed > 0 else "0",
            suspicious_files=f"{suspicious_files} ({(suspicious_files/total_processed*100):.1f}%)" if total_processed > 0 else "0",
            ignored_files=f"{ignored_files} ({(ignored_files/total_processed*100):.1f}%)" if total_processed > 0 else "0",
            reports_saved=", ".join(reports) if reports else None
        )
        
        # Color the summary based on results
        if suspicious_files > 0:
            print(colorize(summary, 'red'))
        elif ignored_files > 0:
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
            print("\nFile Analysis Results:")
            print("-" * 50)
            print(f"Filename: {result['filename']}")
            print(f"Declared type: {os.path.splitext(result['filename'])[1].upper() or 'None'}")
            print(f"Actual type (from headers): {result['actual_type']}")
            print(f"File size: {result['filesize']:,} bytes")
            print(f"SHA256: {result['sha256']}")
            print(f"\nRisk Assessment: {result['risk_level']}")
            
            if result['reasons']:
                print("\nFindings:")
                for reason in result['reasons']:
                    if 'ALERT' in reason:
                        print(colorize(f"❌ {reason}", 'red'))
                    elif 'Warning' in reason or 'Suspicious' in reason:
                        print(colorize(f"⚠️ {reason}", 'yellow'))
                    else:
                        print(f"ℹ️ {reason}")
                        
            print("\nRecommendation:")
            if result['risk_level'] == 'Dangerous':
                print(colorize("DO NOT OPEN! This file shows strong indicators of malware.", 'red'))
            elif result['risk_level'] == 'Suspicious':
                print(colorize("Exercise caution. File shows suspicious characteristics.", 'yellow'))
            else:
                print(colorize("File appears to be safe based on analysis.", 'green'))
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
