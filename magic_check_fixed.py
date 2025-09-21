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

class MagicCheck:
    def scan_directory(self, directory: str) -> List[Dict]:
        """Scan a directory recursively and return analysis results for all files."""
        results = []
        total_files = 0
        safe_files = 0
        suspicious_files = 0

        for root, _, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    result = self.check_file(filepath)
                    if result:
                        results.append(result)
                        if result['risk_level'] == 'Safe':
                            safe_files += 1
                        elif result['risk_level'] == 'Suspicious':
                            suspicious_files += 1
                    total_files += 1  # Count all files, even if result is None
                except Exception as e:
                    print(f"Error processing {filepath}: {str(e)}")
                    continue

        # Print summary
        print("\nDirectory Scan Summary:")
        print(f"Total Files: {total_files}")
        print(f"Safe Files: {safe_files}")
        print(f"Suspicious Files: {suspicious_files}")

        return results

def main():
    checker = MagicCheck()
    directory = input("Enter directory to scan: ")
    checker.scan_directory(directory)

if __name__ == "__main__":
    main()
