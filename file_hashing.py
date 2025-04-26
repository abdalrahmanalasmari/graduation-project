#!/usr/bin/env python3
import hashlib
from typing import Tuple, Optional, Dict

def compute_hashes(file_path: str) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    hashers = {
        'MD5': hashlib.md5(),
        'SHA-1': hashlib.sha1(),
        'SHA-256': hashlib.sha256(),
        'SHA-512': hashlib.sha512()
    }
    try:
        with open(file_path, 'rb') as f:
            while (chunk := f.read(8192)):
                for hasher in hashers.values():
                    hasher.update(chunk)
    except FileNotFoundError:
        return None, f"File not found: {file_path}"
    except PermissionError:
        return None, f"Permission denied: {file_path}"
    except Exception as e:
        return None, f"An unexpected error occurred: {e}"
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}, None

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python file_hashing.py <file1> [<file2> ...]")
        sys.exit(1)
    for file_path in sys.argv[1:]:
        hashes, error = compute_hashes(file_path)
        if error:
            print(error)
        else:
            print(f"\nHashes for '{file_path}':")
            for hash_name, hash_value in hashes.items():
                print(f"{hash_name}: {hash_value}")
