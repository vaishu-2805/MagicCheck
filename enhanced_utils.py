from typing import Dict, List, Optional
import math
import os
import re
import mimetypes
from pathlib import Path

class SuspicionScorer:
    @staticmethod
    def get_risk_level(score: float) -> str:
        if score < 30:
            return "LOW"
        elif score < 70:
            return "MEDIUM"
        else:
            return "HIGH"

    @staticmethod
    def calculate_score(details: dict) -> dict:
        """Calculate a suspicion score and return score details."""
        if not details:
            return {'score': 0, 'risk_level': 'UNKNOWN', 'score_reasons': []}
        """Calculate a detailed suspicion score from 0-100."""
        score = 0
        reasons = []
        
        # Base weights for different factors
        WEIGHTS = {
            'extension_mismatch': 30,
            'suspicious_patterns': 20,
            'high_entropy': 15,
            'archive_malicious': 25,
            'hidden_data': 20,
            'double_extension': 25,
            'unicode_tricks': 20,
            'compression_anomaly': 15,
            'nested_archives': 10,
            'path_traversal': 25
        }
        
        # Extension mismatch
        if details.get('actual_type') != "Unknown":
            claimed_ext = details.get('claimed_extension', '').lower()
            if claimed_ext in details.get('extension_map', {}) and \
               details['extension_map'][claimed_ext] != details['actual_type']:
                score += WEIGHTS['extension_mismatch']
                reasons.append(f"Extension mismatch: claims {claimed_ext}, actually {details['actual_type']}")

        # Suspicious patterns in filename
        filename_analysis = details.get('filename_analysis', {})
        if filename_analysis.get('suspicious_patterns'):
            pattern_score = min(len(filename_analysis['suspicious_patterns']) * 10, WEIGHTS['suspicious_patterns'])
            score += pattern_score
            reasons.append(f"Found {len(filename_analysis['suspicious_patterns'])} suspicious patterns")

        # High entropy
        if details.get('high_entropy'):
            entropy_score = WEIGHTS['high_entropy'] * (details.get('entropy', 0) / 8.0)  # normalize to 0-8 scale
            score += entropy_score
            reasons.append(f"High entropy: {details.get('entropy', 0):.2f}")

        # Archive analysis
        archive_analysis = details.get('archive_analysis', {})
        if archive_analysis:
            # Malicious archive contents
            if archive_analysis.get('is_malicious'):
                score += WEIGHTS['archive_malicious']
                reasons.append("Malicious archive contents detected")
            
            # Nested archives (potential evasion technique)
            if archive_analysis.get('nested_archives'):
                nested_score = min(len(archive_analysis['nested_archives']) * 5, WEIGHTS['nested_archives'])
                score += nested_score
                reasons.append(f"Found {len(archive_analysis['nested_archives'])} nested archives")
            
            # Compression anomalies
            if archive_analysis.get('compression_anomalies'):
                score += WEIGHTS['compression_anomaly']
                reasons.append("Abnormal compression ratios detected")
            
            # Path traversal attempts
            if archive_analysis.get('path_traversal_attempts'):
                score += WEIGHTS['path_traversal']
                reasons.append("Path traversal attempts detected")

        # Double extension
        if filename_analysis.get('double_extension'):
            if any(details.get('filepath', '').lower().endswith(ext) for ext in ['.exe', '.dll', '.bat', '.ps1']):
                score += WEIGHTS['double_extension']
                reasons.append("Executable double extension detected")

        # Unicode tricks
        if filename_analysis.get('unicode_tricks'):
            score += WEIGHTS['unicode_tricks']
            reasons.append("Unicode manipulation detected")

        # Hidden data
        if details.get('hidden_data_analysis', {}).get('has_hidden_data'):
            score += WEIGHTS['hidden_data']
            reasons.append("Hidden data detected")

        # Normalize score to 0-100
        final_score = min(round(score), 100)
        
        return {
            'score': final_score,
            'risk_level': SuspicionScorer.get_risk_level(final_score),
            'score_reasons': reasons
        }

class EnhancedFileTypeDetector:
    @staticmethod
    def detect_file_type(filepath: str) -> str:
        """Enhanced file type detection using multiple methods."""
        # Initialize mimetypes with common types
        mimetypes.init()
        
        # Check if it's a git object
        if '.git/objects' in filepath:
            return 'application/x-git-object'
            
        # Check file extension first for specific types
        ext = os.path.splitext(filepath)[1].lower()
        if ext == '.py':
            return 'text/x-python'
        elif ext == '.pyc':
            return 'application/x-python-code'
        elif ext in ['.git', '.gitignore']:
            return 'application/x-git'
        elif ext == '.md':
            return 'text/markdown'
            
        # Try mimetypes
        file_type, _ = mimetypes.guess_type(filepath)
        if file_type:
            return file_type
            
        # Check for text files
        try:
            with open(filepath, 'rb') as f:
                content = f.read(1024)  # Read first 1KB
                if all(32 <= byte <= 126 or byte in (9, 10, 13) for byte in content):
                    # Check for common text file types
                    ext = os.path.splitext(filepath)[1].lower()
                    if ext in ['.md', '.txt', '.log']:
                        return 'text/plain'
                    elif ext in ['.json']:
                        return 'application/json'
                    elif ext in ['.xml']:
                        return 'application/xml'
                    elif ext in ['.yml', '.yaml']:
                        return 'application/yaml'
                    return 'text/plain'
        except:
            pass
        
        # Fallback to checking file signatures
        try:
            with open(filepath, 'rb') as f:
                header = f.read(8)  # Read first 8 bytes
                
                # Common file signatures
                if header.startswith(b'\xFF\xD8\xFF'):
                    return 'image/jpeg'
                elif header.startswith(b'\x89PNG\r\n\x1a\n'):
                    return 'image/png'
                elif header.startswith(b'GIF87a') or header.startswith(b'GIF89a'):
                    return 'image/gif'
                elif header.startswith(b'%PDF'):
                    return 'application/pdf'
                elif header.startswith(b'PK\x03\x04'):
                    return 'application/zip'
                elif header.startswith(b'\x7FELF'):
                    return 'application/x-elf'
                elif header.startswith(b'MZ'):
                    return 'application/x-dosexec'
        except:
            pass
            
        return "application/octet-stream"

    @staticmethod
    def check_steganography(filepath: str) -> dict:
        """Check for potential steganography in supported file types."""
        result = {
            'has_hidden_data': False,
            'details': []
        }
        
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                
                # Check PNG
                if data.startswith(b'\x89PNG'):
                    iend_pos = data.find(b'IEND')
                    if iend_pos != -1 and len(data) > iend_pos + 8:
                        result['has_hidden_data'] = True
                        result['details'].append("Data found after PNG EOF marker")
                
                # Check JPEG
                elif data.startswith(b'\xFF\xD8'):
                    if not data.rstrip(b'\0').endswith(b'\xFF\xD9'):
                        result['has_hidden_data'] = True
                        result['details'].append("Irregular JPEG EOF marker")
                
                # Check PDF
                elif data.startswith(b'%PDF'):
                    if b'%%EOF' in data and data.rstrip(b'\0')[data.rindex(b'%%EOF')+5:]:
                        result['has_hidden_data'] = True
                        result['details'].append("Data found after PDF EOF marker")
                
        except Exception as e:
            result['details'].append(f"Error checking for steganography: {str(e)}")
        
        return result

class DirectoryScanSummary:
    def __init__(self):
        self.summary = {
            'total_files': 0,
            'safe_files': 0,
            'suspicious_files': 0,
            'risk_levels': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0},
            'file_types': {},
            'suspicious_extensions': {},
            'total_size': 0,
            'average_score': 0.0,
            'score_distribution': {
                '0-20': 0, '21-40': 0, '41-60': 0, 
                '61-80': 0, '81-100': 0
            }
        }
        self._scores = []  # For calculating average

    def add_result(self, result: dict):
        """Add a scan result to the summary."""
        self.summary['total_files'] += 1
        self.summary['total_size'] += result.get('filesize', 0)
        
        # Track file types with better categorization
        file_type = result.get('actual_type', 'Unknown')
        mime_type = result.get('mime_type', '')
        
        # Improved file type categorization
        if '.git/objects/' in result.get('filepath', ''):
            file_type = 'GIT-OBJECT'
        elif file_type == 'Unknown' and mime_type:
            file_type = mime_type.split('/')[-1].upper()
            
        self.summary['file_types'][file_type] = self.summary['file_types'].get(file_type, 0) + 1
        
        # Process suspicion score
        score_details = result.get('suspicion_score', {})
        score = score_details.get('score', 0)
        self._scores.append(score)
        
        # Update risk level counts
        risk_level = score_details.get('risk_level', 'LOW')
        self.summary['risk_levels'][risk_level] = self.summary['risk_levels'].get(risk_level, 0) + 1
        
        # Update score distribution
        score_range = f"{(score // 20) * 20 + 1}-{min((score // 20 + 1) * 20, 100)}"
        self.summary['score_distribution'][score_range] = self.summary['score_distribution'].get(score_range, 0) + 1
        
        # Track suspicious vs safe with better logic
        is_suspicious = result.get('is_suspicious', False)
        ext = result.get('claimed_extension', '').lower()
        
        # Known safe file types
        SAFE_TYPES = {'PYTHON', 'PYTHON-BYTECODE', 'JSON', 'MARKDOWN', 'TEXT', 'GIT-OBJECT', 'GIT-CONFIG'}
        
        # Check if the file is suspicious
        if is_suspicious and ext and ext not in ['.py', '.pyc', '.json', '.md', '.txt', '.git']:
            self.summary['suspicious_files'] += 1
            self.summary['suspicious_extensions'][ext] = self.summary['suspicious_extensions'].get(ext, 0) + 1
        else:
            if file_type in SAFE_TYPES or any(safe_path in result.get('filepath', '') for safe_path in ['.git/', '__pycache__/']):
                self.summary['safe_files'] += 1
            elif is_suspicious:
                self.summary['suspicious_files'] += 1
            else:
                self.summary['safe_files'] += 1
        
        # Update average score
        self.summary['average_score'] = sum(self._scores) / len(self._scores)

    def get_summary(self) -> dict:
        """Get the current summary statistics."""
        return self.summary
