import math
import os
import zipfile
import re
from typing import List, Set, Dict, Any, Optional
from datetime import datetime
import json
import csv

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
    Return a set of suspicious filename patterns focused on actual security threats.
    """
    return {
        r'\.exe\.[^.]+$',  # Hidden executable after another extension
        r'\.(exe|bat|cmd|ps1|vbs|js|wsf|msi|scr)\.',  # Dangerous extension not at end
        r'_(exe|dll|bat|cmd|ps1|vbs|js|msi|scr)\.', # Attempted extension hiding
        r'[<>|&;$()]',  # Shell special characters
        r'\\\\+[^\\]',  # Multiple backslashes (path traversal attempt)
        r'\.\.|~\$',    # Path traversal or temp file markers
        r'encrypted|passwd|credentials', # Sensitive data indicators
        r'exploit|payload|malware|virus|trojan|backdoor',  # Obvious malicious terms
    }

class SuspicionScorer:
    @staticmethod
    def score_file(filepath: str, file_type: str, entropy: float) -> tuple[float, list[str]]:
        """Calculate suspicion score and reasons for a file."""
        score = 0.0
        reasons = []
        
        # Basic checks
        if file_type in ['EXE', 'DLL', 'SCR']:
            if entropy > 7.0:
                score += 0.5
                reasons.append(f"High entropy ({entropy:.2f}) executable")
                
        # Add more scoring logic as needed
        
        return score, reasons

class EnhancedFileTypeDetector:
    def __init__(self):
        self.type_signatures = {
            b'\x4D\x5A': 'EXE',
            b'\x7F\x45\x4C\x46': 'ELF',
            b'\x89\x50\x4E\x47': 'PNG',
            b'\xFF\xD8\xFF': 'JPEG',
            # Add more signatures as needed
        }
    
    def detect_type(self, data: bytes) -> str:
        """Detect file type from binary data."""
        for sig, ftype in self.type_signatures.items():
            if data.startswith(sig):
                return ftype
        return "Unknown"

class DirectoryScanSummary:
    def __init__(self):
        self.total_files = 0
        self.suspicious_files = 0
        self.safe_files = 0
        self.errors = 0
        
    def add_result(self, result: dict):
        """Add a scan result to the summary."""
        self.total_files += 1
        if result.get('is_suspicious'):
            self.suspicious_files += 1
        else:
            self.safe_files += 1

class ReportExporter:
    @staticmethod
    def to_json(results: List[Dict], filepath: str):
        """Export results to JSON format."""
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
    
    @staticmethod
    def to_csv(results: List[Dict], filepath: str):
        """Export results to CSV format."""
        if not results:
            return
            
        headers = ['filepath', 'filename', 'filesize', 'actual_type', 'risk_level', 'reasons', 'sha256']
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for result in results:
                row = {k: str(result.get(k, '')) for k in headers}
                writer.writerow(row)
                
    @staticmethod
    def to_html(results: List[Dict], filepath: str):
        """Export results to HTML format."""
        if not results:
            return
            
        html_template = '''<!DOCTYPE html>
<html>
<head>
    <title>MagicCheck Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f5f5f5; }}
        .safe {{ color: green; }}
        .suspicious {{ color: red; }}
        .summary {{ margin: 20px 0; padding: 10px; background-color: #f9f9f9; }}
    </style>
</head>
<body>
    <h1>MagicCheck Scan Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Files: {total}</p>
        <p>Safe Files: <span class="safe">{safe}</span></p>
        <p>Suspicious Files: <span class="suspicious">{suspicious}</span></p>
        <p>Scan Date: {date}</p>
    </div>
    <h2>Detailed Results</h2>
    <table>
        <tr>
            <th>Filename</th>
            <th>Type</th>
            <th>Size</th>
            <th>Risk Level</th>
            <th>Reasons</th>
        </tr>
        {rows}
    </table>
</body>
</html>'''
        # Generate statistics
        total = len(results)
        safe = sum(1 for r in results if r['risk_level'] == 'Safe')
        suspicious = total - safe
        
        # Generate table rows
        rows = []
        for result in results:
            reason_list = result.get('reasons', [])
            reasons = "<br>".join(reason_list) if reason_list else "None"
            risk_class = 'suspicious' if result['risk_level'] == 'Suspicious' else 'safe'
            
            row = f"""
            <tr>
                <td>{result['filename']}</td>
                <td>{result['actual_type']}</td>
                <td>{result['filesize']:,} bytes</td>
                <td class="{risk_class}">{result['risk_level']}</td>
                <td>{reasons}</td>
            </tr>"""
            rows.append(row)
            
        # Fill template
        formatted_html = html_template.format(
            total=total,
            safe=f"{safe} ({safe/total*100:.1f}%)",
            suspicious=f"{suspicious} ({suspicious/total*100:.1f}%)",
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            rows="\n".join(rows)
        )
        
        # Write to file
        with open(filepath, 'w') as f:
            f.write(formatted_html)
