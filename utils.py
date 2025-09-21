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

def analyze_archive_contents(filepath: str) -> dict:
    """
    Perform detailed analysis of archive contents.
    Returns a dictionary with analysis results.
    """
    results = {
        "is_malicious": False,
        "total_files": 0,
        "suspicious_files": [],
        "high_entropy_files": [],
        "nested_archives": [],
        "path_traversal_attempts": [],
        "compression_anomalies": [],
        "file_types": {},
        "total_size": 0,
        "compressed_size": 0
    }

    try:
        dangerous_exts = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.msi', '.scr'}
        archive_exts = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'}
        
        with zipfile.ZipFile(filepath, 'r') as zip_ref:
            results["total_files"] = len(zip_ref.filelist)
            
            for file_info in zip_ref.infolist():
                filename = file_info.filename.lower()
                file_ext = os.path.splitext(filename)[1]
                
                # Track file types
                results["file_types"][file_ext] = results["file_types"].get(file_ext, 0) + 1
                
                # Track sizes
                results["total_size"] += file_info.file_size
                results["compressed_size"] += file_info.compress_size
                
                # Check for dangerous files
                if any(filename.endswith(ext) for ext in dangerous_exts):
                    results["suspicious_files"].append({
                        "name": file_info.filename,
                        "reason": "Dangerous extension"
                    })
                
                # Check for nested archives
                if any(filename.endswith(ext) for ext in archive_exts):
                    results["nested_archives"].append(file_info.filename)
                
                # Check for path traversal
                if '../' in file_info.filename or '..\\' in file_info.filename:
                    results["path_traversal_attempts"].append(file_info.filename)
                
                # Check compression ratio
                if file_info.compress_size > 0:
                    ratio = file_info.file_size / file_info.compress_size
                    if ratio > 1000:
                        results["compression_anomalies"].append({
                            "name": file_info.filename,
                            "ratio": ratio
                        })
                
                # Check file entropy
                try:
                    data = zip_ref.read(file_info.filename)
                    entropy = calculate_entropy(data)
                    if entropy > 7.0 and not any(filename.endswith(ext) for ext in archive_exts):
                        results["high_entropy_files"].append({
                            "name": file_info.filename,
                            "entropy": entropy
                        })
                except:
                    pass  # Skip if we can't read the file
        
        # Determine if the archive is potentially malicious
        results["is_malicious"] = (
            len(results["suspicious_files"]) > 0 or
            len(results["path_traversal_attempts"]) > 0 or
            len(results["compression_anomalies"]) > 0 or
            (len(results["nested_archives"]) > 3)  # Too many nested archives is suspicious
        )
                
    except zipfile.BadZipFile:
        return {"error": "Invalid ZIP file"}
    except Exception as e:
        return {"error": str(e)}
        
    return results

def is_potentially_malicious_archive(filepath: str) -> bool:
    """
    Check if an archive contains potentially malicious files.
    """
    results = analyze_archive_contents(filepath)
    return results.get("is_malicious", False) or "error" in results

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
