import math
import os
import zipfile
import re
from typing import List, Set

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    
    # Calculate frequency of each byte
    frequencies = {}
    for byte in data:
        frequencies[byte] = frequencies.get(byte, 0) + 1
    
    # Calculate entropy
    entropy = 0
    for freq in frequencies.values():
        probability = freq / len(data)
        entropy -= probability * math.log2(probability)
    
    return entropy

def detect_double_extension(filename: str) -> bool:
    """
    Detect if a filename has multiple extensions.
    Example: photo.jpg.exe
    """
    # Split all extensions
    parts = filename.split('.')
    if len(parts) > 2:
        # Check if the last extension is a known executable
        dangerous_exts = {'exe', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'wsf', 'msi', 'scr'}
        return parts[-1].lower() in dangerous_exts
    return False

def detect_unicode_tricks(filename: str) -> bool:
    """
    Detect Unicode manipulation tricks in filenames.
    Examples: 𝖯hoto.jpg, рhoto.jpg (Cyrillic 'р')
    """
    # Check for non-ASCII characters
    if not all(ord(c) < 128 for c in filename):
        # Specific checks for common substitutions
        suspicious_chars = {
            'А': 'A',  # Cyrillic
            'В': 'B',
            'С': 'C',
            'Е': 'E',
            'Р': 'P',
            '𝖠': 'A',  # Mathematical letters
            '𝖡': 'B',
            '𝖢': 'C'
        }
        
        for sus_char in suspicious_chars:
            if sus_char in filename:
                return True
                
        # Check for zero-width characters
        zero_width = ['\u200B', '\uFEFF', '\u200C']
        return any(c in filename for c in zero_width)
    
    return False

def is_potentially_malicious_archive(filepath: str) -> bool:
    """
    Check if an archive contains potentially malicious files.
    """
    try:
        dangerous_exts = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.msi', '.scr'}
        with zipfile.ZipFile(filepath, 'r') as zip_ref:
            # Check for suspicious files in the archive
            for file_info in zip_ref.infolist():
                # Check extensions
                if any(file_info.filename.lower().endswith(ext) for ext in dangerous_exts):
                    return True
                
                # Check for path traversal attempts
                if '../' in file_info.filename or '..\\' in file_info.filename:
                    return True
                
                # Check for suspiciously large compression ratios
                if file_info.compress_size > 0:  # Avoid division by zero
                    ratio = file_info.file_size / file_info.compress_size
                    if ratio > 1000:  # Suspicious compression ratio
                        return True
                
    except zipfile.BadZipFile:
        # Not a valid zip file
        return False
    except Exception:
        # Any other error, better safe than sorry
        return True
        
    return False

def scan_directory(directory: str) -> List[str]:
    """
    Recursively scan a directory for files to check.
    Returns a list of file paths.
    """
    file_list = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_list.append(os.path.join(root, file))
    return file_list

def get_suspicious_patterns() -> Set[str]:
    """
    Return a set of suspicious filename patterns.
    """
    return {
        r'\.exe\.',  # Hidden executable extension
        r'\.{2,}',   # Multiple dots
        r'\s{2,}',   # Multiple spaces
        r'[^a-zA-Z0-9\s\.-]',  # Special characters
        r'\.(exe|dll|bat|cmd|ps1|vbs|js|wsf|msi|scr)$'  # Dangerous extensions
    }
