from typing import List, Dict
from datetime import datetime

class ReportExporter:
    @staticmethod
    def to_html(results: List[Dict], filepath: str) -> None:
        """Export results to an HTML file with basic styling."""
        if not results:
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>MagicCheck Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .suspicious {{ color: #d73a49; }}
        .safe {{ color: #28a745; }}
        .warning {{ color: #f6a935; }}
    </style>
</head>
<body>
    <h1>MagicCheck Analysis Report</h1>
    <p>Generated on: {timestamp}</p>
    <table>
        <tr>
            <th>File</th>
            <th>Size</th>
            <th>Type</th>
            <th>Risk Level</th>
            <th>Score</th>
            <th>SHA256</th>
        </tr>"""

        # Add table rows
        for result in results:
            risk_level = "safe" if not result.get('is_suspicious') else "suspicious"
            risk_class = "safe" if not result.get('is_suspicious') else "suspicious"
            
            html_content += f"""
        <tr>
            <td>{result.get('filepath', 'N/A')}</td>
            <td>{result.get('filesize', 0):,}</td>
            <td>{result.get('actual_type', 'Unknown')}</td>
            <td class="{risk_class}">{risk_level.upper()}</td>
            <td>{result.get('suspicion_score', {}).get('score', 0)}</td>
            <td>{result.get('sha256', 'N/A')}</td>
        </tr>"""

        # Close tags
        html_content += """
    </table>
</body>
</html>
"""

        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

    @staticmethod
    def to_json(results: List[Dict], filepath: str) -> None:
        """Export results to a JSON file."""
        import json
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)

    @staticmethod
    def to_csv(results: List[Dict], filepath: str) -> None:
        """Export results to a CSV file."""
        import csv
        
        if not results:
            return
            
        fieldnames = ['filepath', 'filesize', 'actual_type', 'is_suspicious', 
                     'suspicious_reasons', 'sha256', 'entropy']
                     
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for result in results:
                # Clean and prepare row data
                row = {
                    'filepath': result.get('filepath', ''),
                    'filesize': result.get('filesize', 0),
                    'actual_type': result.get('actual_type', 'Unknown'),
                    'is_suspicious': result.get('is_suspicious', False),
                    'suspicious_reasons': '; '.join(result.get('suspicious_reasons', [])),
                    'sha256': result.get('sha256', 'N/A'),
                    'entropy': result.get('entropy', 0)
                }
                writer.writerow(row)
