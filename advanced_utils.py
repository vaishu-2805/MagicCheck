import json
import csv
from typing import Dict, List, Union, Optional
import mimetypes
from datetime import datetime
import os

class SuspicionScorer:
    """Calculates a suspicion score based on various factors."""
    
    SCORE_WEIGHTS = {
        'extension_mismatch': 50,
        'high_entropy': 20,
        'suspicious_archive': 30,
        'double_extension': 40,
        'unicode_tricks': 35,
        'hidden_stream': 25,
        'suspicious_patterns': 15,
        'path_traversal': 45,
        'high_compression': 20,
        'executable_in_archive': 35,
        'hidden_data': 40
    }

    @classmethod
    def calculate_score(cls, analysis_results: dict) -> dict:
        """Calculate suspicion score from analysis results."""
        score = 0
        reasons = []

        # Extension mismatch
        if analysis_results.get('actual_type') != 'Unknown':
            ext_map = analysis_results.get('extension_map', {})
            claimed_ext = analysis_results.get('claimed_extension', '').lower()
            if ext_map.get(claimed_ext) != analysis_results.get('actual_type'):
                score += cls.SCORE_WEIGHTS['extension_mismatch']
                reasons.append('Extension mismatch')

        # High entropy
        if analysis_results.get('high_entropy'):
            score += cls.SCORE_WEIGHTS['high_entropy']
            reasons.append(f"High entropy ({analysis_results.get('entropy', 0):.2f})")

        # Archive analysis
        archive_analysis = analysis_results.get('archive_analysis', {})
        if archive_analysis:
            if archive_analysis.get('suspicious_files'):
                score += cls.SCORE_WEIGHTS['suspicious_archive']
                reasons.append('Suspicious files in archive')
            if len(archive_analysis.get('nested_archives', [])) > 2:
                score += cls.SCORE_WEIGHTS['suspicious_archive']
                reasons.append('Multiple nested archives')
            if archive_analysis.get('path_traversal_attempts'):
                score += cls.SCORE_WEIGHTS['path_traversal']
                reasons.append('Path traversal attempt detected')

        # Filename analysis
        filename_analysis = analysis_results.get('filename_analysis', {})
        if filename_analysis.get('double_extension'):
            score += cls.SCORE_WEIGHTS['double_extension']
            reasons.append('Double extension detected')
        if filename_analysis.get('unicode_tricks'):
            score += cls.SCORE_WEIGHTS['unicode_tricks']
            reasons.append('Unicode manipulation detected')

        # Cap the score at 100
        score = min(score, 100)

        # Determine risk level
        risk_level = 'LOW'
        if score >= 70:
            risk_level = 'HIGH'
        elif score >= 40:
            risk_level = 'MEDIUM'

        return {
            'score': score,
            'risk_level': risk_level,
            'reasons': reasons
        }

class FileTypeDetector:
    """Enhanced file type detection using multiple methods."""
    
    TEXT_SIGNATURES = {
        'html': (b'<!DOCTYPE', b'<html', b'<HTML'),
        'xml': (b'<?xml', b'<xml'),
        'json': (b'{', b'['),
        'markdown': (b'# ', b'## ', b'### '),
        'csv': (b',,,', b';;;'),  # Simple heuristic for CSV files
    }

    @classmethod
    def detect_text_type(cls, content: bytes) -> Optional[str]:
        """Detect text-based file types."""
        try:
            # Try to decode as text
            content_start = content[:1024].decode('utf-8')
            
            # Check for common text file signatures
            for file_type, signatures in cls.TEXT_SIGNATURES.items():
                if any(sig in content for sig in signatures):
                    return file_type.upper()
            
            # If it's decodable as text but no specific signature, it's probably plain text
            return 'TEXT'
        except UnicodeDecodeError:
            return None

    @classmethod
    def detect_hidden_data(cls, filepath: str, file_type: str) -> dict:
        """Detect hidden data in files."""
        results = {
            'has_hidden_data': False,
            'details': []
        }

        try:
            with open(filepath, 'rb') as f:
                content = f.read()

            if file_type == 'PNG':
                # Check for data after IEND chunk
                png_end = content.find(b'IEND') + 8
                if png_end < len(content):
                    results['has_hidden_data'] = True
                    results['details'].append(f'Found {len(content) - png_end} bytes after PNG EOF')

            elif file_type == 'JPG/JPEG':
                # Check for data after EOI marker
                jpg_end = content.rfind(b'\xFF\xD9') + 2
                if jpg_end < len(content):
                    results['has_hidden_data'] = True
                    results['details'].append(f'Found {len(content) - jpg_end} bytes after JPEG EOI')

            elif file_type == 'PDF':
                # Check for data after %%EOF
                pdf_end = content.rfind(b'%%EOF') + 5
                if pdf_end < len(content):
                    results['has_hidden_data'] = True
                    results['details'].append(f'Found {len(content) - pdf_end} bytes after PDF EOF')

        except Exception as e:
            results['error'] = str(e)

        return results

class ReportExporter:
    """Handles exporting scan results to various formats."""

    @staticmethod
    def to_json(results: Union[dict, List[dict]], filepath: str):
        """Export results to JSON file."""
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)

    @staticmethod
    def to_csv(results: Union[dict, List[dict]], filepath: str):
        """Export results to CSV file."""
        if not isinstance(results, list):
            results = [results]

        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow(['Filename', 'Type', 'Extension', 'Suspicious', 'Score', 'Risk Level', 'SHA256'])
            # Write data
            for result in results:
                writer.writerow([
                    result.get('filepath', ''),
                    result.get('actual_type', 'Unknown'),
                    result.get('claimed_extension', ''),
                    result.get('is_suspicious', False),
                    result.get('suspicion_score', {}).get('score', 0),
                    result.get('suspicion_score', {}).get('risk_level', 'LOW'),
                    result.get('sha256', '')
                ])

    @staticmethod
    def to_html(results: Union[dict, List[dict]], filepath: str):
        """Export results to HTML file with basic styling."""
        if not isinstance(results, list):
            results = [results]

        html_content = """
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .suspicious { background-color: #ffe6e6; }
                .safe { background-color: #e6ffe6; }
                .warning { color: #ff4444; }
            </style>
        </head>
        <body>
            <h1>MagicCheck Scan Report</h1>
            <p>Generated: {date}</p>
            <table>
                <tr>
                    <th>File</th>
                    <th>Type</th>
                    <th>Extension</th>
                    <th>Score</th>
                    <th>Risk Level</th>
                    <th>SHA256</th>
                </tr>
        """.format(date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        for result in results:
            row_class = 'suspicious' if result.get('is_suspicious') else 'safe'
            html_content += f"""
                <tr class="{row_class}">
                    <td>{result.get('filepath', '')}</td>
                    <td>{result.get('actual_type', 'Unknown')}</td>
                    <td>{result.get('claimed_extension', '')}</td>
                    <td>{result.get('suspicion_score', {}).get('score', 0)}/100</td>
                    <td>{result.get('suspicion_score', {}).get('risk_level', 'LOW')}</td>
                    <td>{result.get('sha256', '')}</td>
                </tr>
            """

        html_content += """
            </table>
        </body>
        </html>
        """

        with open(filepath, 'w') as f:
            f.write(html_content)

class DirectoryScanSummary:
    """Generates summary statistics for directory scans."""
    
    def __init__(self):
        self.total_files = 0
        self.suspicious_files = 0
        self.risk_levels = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
        self.file_types = {}
        self.total_size = 0
        self.suspicious_extensions = {}

    def add_result(self, result: dict):
        """Add a scan result to the summary."""
        self.total_files += 1
        self.total_size += result.get('filesize', 0)
        
        if result.get('is_suspicious'):
            self.suspicious_files += 1
            ext = result.get('claimed_extension', 'none')
            self.suspicious_extensions[ext] = self.suspicious_extensions.get(ext, 0) + 1

        risk_level = result.get('suspicion_score', {}).get('risk_level', 'LOW')
        self.risk_levels[risk_level] = self.risk_levels.get(risk_level, 0) + 1

        file_type = result.get('actual_type', 'Unknown')
        self.file_types[file_type] = self.file_types.get(file_type, 0) + 1

    def get_summary(self) -> dict:
        """Get the summary statistics."""
        return {
            'total_files': self.total_files,
            'suspicious_files': self.suspicious_files,
            'safe_files': self.total_files - self.suspicious_files,
            'risk_levels': self.risk_levels,
            'file_types': self.file_types,
            'total_size': self.total_size,
            'suspicious_extensions': self.suspicious_extensions
        }
