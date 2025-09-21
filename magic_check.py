#!/usr/bin/env python3

import os
import struct
import hashlib
from typing import Dict, Tuple, Optional

class MagicCheck:
    def __init__(self):
        # Dictionary of known file signatures (magic numbers)
        self.signatures: Dict[bytes, str] = {
            b'\xFF\xD8\xFF': 'JPG/JPEG',
            b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': 'PNG',
            b'\x25\x50\x44\x46': 'PDF',
            b'\x4D\x5A': 'EXE',
            b'\x50\x4B\x03\x04': 'ZIP',
            b'\x7F\x45\x4C\x46': 'ELF',
            b'\x52\x61\x72\x21\x1A\x07': 'RAR',
            b'\x47\x49\x46\x38': 'GIF'
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

    def check_file(self, filepath: str) -> Tuple[bool, dict]:
        """
        Check if a file's actual type matches its extension.
        Returns: (is_suspicious, details_dict)
        """
        if not os.path.exists(filepath):
            return True, {"error": "File not found", "filepath": filepath}

        # Read magic bytes
        magic_bytes = self.read_magic_bytes(filepath)
        if not magic_bytes:
            return True, {"error": "Could not read file", "filepath": filepath}

        # Get actual file type and claimed extension
        actual_type = self.get_file_type(magic_bytes)
        claimed_ext = self.get_file_extension(filepath)
        
        # Calculate file hash
        file_hash = self.calculate_hash(filepath)

        # Check if file is suspicious
        is_suspicious = False
        if actual_type != "Unknown":
            # Map common extensions to their corresponding file types
            extension_map = {
                'jpg': 'JPG/JPEG',
                'jpeg': 'JPG/JPEG',
                'png': 'PNG',
                'pdf': 'PDF',
                'exe': 'EXE',
                'zip': 'ZIP',
                'elf': 'ELF',
                'rar': 'RAR',
                'gif': 'GIF'
            }
            
            # Get the expected file type for the claimed extension
            expected_type = extension_map.get(claimed_ext.lower())
            
            # File is suspicious if:
            # 1. We know the expected type for this extension AND
            # 2. The actual type doesn't match the expected type
            if expected_type and expected_type != actual_type:
                is_suspicious = True

        return is_suspicious, {
            "filepath": filepath,
            "claimed_extension": claimed_ext,
            "actual_type": actual_type,
            "is_suspicious": is_suspicious,
            "sha256": file_hash
        }

def main():
    checker = MagicCheck()
    
    # Get file path from user and clean it
    filepath = input("Enter the path to the file to check: ").strip('" ')
    
    # Check the file
    is_suspicious, details = checker.check_file(filepath)
    
    # Print results
    print("\n=== File Check Results ===")
    if "error" in details:
        print(f"Error: {details['error']}")
        print(f"File: {details.get('filepath')}")
        return

    print(f"File: {details.get('filepath')}")
    print(f"Claimed Extension: {details.get('claimed_extension', 'None')}")
    print(f"Actual Type: {details.get('actual_type', 'Unknown')}")
    print(f"SHA256: {details.get('sha256', 'N/A')}")
    print(f"\nSUSPICIOUS: {'YES' if is_suspicious else 'NO'}")
    
    if is_suspicious:
        print("\n⚠️ WARNING: File type does not match its extension!")
        print(f"File claims to be: {details.get('claimed_extension')}")
        print(f"But appears to be: {details.get('actual_type')}")
        print("\nThis file may be potentially dangerous.")

if __name__ == "__main__":
    main()
