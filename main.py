import hashlib
import argparse
import os
import time
from datetime import datetime
import csv
import binascii
import base64

# For bcrypt support
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    print("Warning: bcrypt module not available. Install with 'pip install bcrypt' for bcrypt support.")

# For Windows hash support
try:
    import passlib.hash
    PASSLIB_AVAILABLE = True
except ImportError:
    PASSLIB_AVAILABLE = False
    print("Warning: passlib module not available. Install with 'pip install passlib' for Windows hash support.")

def print_banner():
    print("\033[91m" + """
____  _____ ____     _    _     _____ ____ _____ 
|  _ \| ____|  _ \   / \  | |   | ____|  _ \_   _|
| |_) |  _| | | | | / _ \ | |   |  _| | |_) || |  
|  _ <| |___| |_| |/ ___ \| |___| |___|  _ < | |  
|_| \_\_____|____/_/   \_\_____|_____|_| \_\ |_|
    """ + "\033[0m")
    print("\033[91m" + "                  Password Hash Cracker Tool" + "\033[0m")
    print("\033[93m" + "                  Please Use ethically." + "\033[0m")
    print()

def calculate_hash(password, algorithm):
    """Calculate hash of a password using specified algorithm"""
    # Standard algorithms
    if algorithm == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(password.encode()).hexdigest()
    elif algorithm == 'sha3_256':
        return hashlib.sha3_256(password.encode()).hexdigest()
    elif algorithm == 'sha3_512':
        return hashlib.sha3_512(password.encode()).hexdigest()
    
    # Windows specific algorithms
    elif algorithm == 'ntlm':
        if PASSLIB_AVAILABLE:
            return passlib.hash.nthash.hash(password).lower()
        else:
            # Manual NTLM implementation if passlib not available
            try:
                # Convert to UTF-16LE and hash with MD4
                password_utf16 = password.encode('utf-16le')
                md4 = hashlib.new('md4')
                md4.update(password_utf16)
                return md4.hexdigest()
            except:
                raise ValueError("NTLM hashing failed. Install passlib for better support.")
    
    elif algorithm == 'lm':
        if PASSLIB_AVAILABLE:
            try:
                return passlib.hash.lmhash.hash(password).lower()
            except:
                raise ValueError("LM hash only supports ASCII characters and max 14 characters")
        else:
            raise ValueError("LM hash requires passlib module")
    
    # Unix/Linux specific algorithms
    elif algorithm == 'md5_crypt':
        if PASSLIB_AVAILABLE:
            # $1$ format (Linux MD5)
            return passlib.hash.md5_crypt.hash(password)
        else:
            raise ValueError("md5_crypt requires passlib module")
    
    elif algorithm == 'sha256_crypt':
        if PASSLIB_AVAILABLE:
            # $5$ format (Linux SHA-256)
            return passlib.hash.sha256_crypt.hash(password)
        else:
            raise ValueError("sha256_crypt requires passlib module")
    
    elif algorithm == 'sha512_crypt':
        if PASSLIB_AVAILABLE:
            # $6$ format (Linux SHA-512)
            return passlib.hash.sha512_crypt.hash(password)
        else:
            raise ValueError("sha512_crypt requires passlib module")
    
    # bcrypt
    elif algorithm == 'bcrypt':
        if BCRYPT_AVAILABLE:
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        else:
            raise ValueError("bcrypt requires bcrypt module")
    
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

def compare_hash(target_hash, wordlist_path, algorithm):
    """Compare a hash against a wordlist using the specified algorithm"""
    start_time = time.time()
    words_checked = 0
    
    # Special handling for algorithm verification
    is_bcrypt = algorithm == 'bcrypt'
    is_md5_crypt = algorithm == 'md5_crypt'
    is_sha256_crypt = algorithm == 'sha256_crypt'
    is_sha512_crypt = algorithm == 'sha512_crypt'
    
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as wordlist:
            for word in wordlist:
                word = word.strip()
                words_checked += 1
                
                if words_checked % 100000 == 0:
                    print(f"Checked {words_checked} words...")
                
                # Special handling for different hash types
                if is_bcrypt and BCRYPT_AVAILABLE:
                    # bcrypt needs special verification
                    if bcrypt.checkpw(word.encode(), target_hash.encode()):
                        elapsed_time = time.time() - start_time
                        return {
                            "found": True,
                            "original": word,
                            "time_taken": elapsed_time,
                            "words_checked": words_checked
                        }
                elif (is_md5_crypt or is_sha256_crypt or is_sha512_crypt) and PASSLIB_AVAILABLE:
                    # Use passlib to verify crypt-style hashes
                    if is_md5_crypt:
                        verified = passlib.hash.md5_crypt.verify(word, target_hash)
                    elif is_sha256_crypt:
                        verified = passlib.hash.sha256_crypt.verify(word, target_hash)
                    elif is_sha512_crypt:
                        verified = passlib.hash.sha512_crypt.verify(word, target_hash)
                    
                    if verified:
                        elapsed_time = time.time() - start_time
                        return {
                            "found": True,
                            "original": word,
                            "time_taken": elapsed_time,
                            "words_checked": words_checked
                        }
                else:
                    # Standard hash comparison
                    current_hash = calculate_hash(word, algorithm)
                    if current_hash.lower() == target_hash.lower():
                        elapsed_time = time.time() - start_time
                        return {
                            "found": True,
                            "original": word,
                            "time_taken": elapsed_time,
                            "words_checked": words_checked
                        }
    except Exception as e:
        print(f"Error reading wordlist: {e}")
        return {"found": False, "error": str(e)}
    
    elapsed_time = time.time() - start_time
    return {
        "found": False,
        "time_taken": elapsed_time,
        "words_checked": words_checked
    }

def process_hash_file(hash_file_path, wordlist_path, algorithm):
    """Process a file containing multiple hashes"""
    results = []
    
    try:
        with open(hash_file_path, 'r') as hash_file:
            hashes = [line.strip() for line in hash_file if line.strip()]
            
            print(f"Loaded {len(hashes)} hashes from file")
            
            for i, target_hash in enumerate(hashes):
                print(f"Processing hash {i+1}/{len(hashes)}: {target_hash}")
                result = compare_hash(target_hash, wordlist_path, algorithm)
                result["hash"] = target_hash
                results.append(result)
                
    except Exception as e:
        print(f"Error processing hash file: {e}")
        
    return results

def save_report(results, output_file):
    """Save comparison results to a CSV file"""
    try:
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['hash', 'found', 'original', 'time_taken', 'words_checked']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                writer.writerow({
                    'hash': result.get('hash', 'N/A'),
                    'found': result.get('found', False),
                    'original': result.get('original', 'Not found'),
                    'time_taken': f"{result.get('time_taken', 0):.2f} seconds",
                    'words_checked': result.get('words_checked', 0)
                })
        print(f"Report saved to {output_file}")
        return True
    except Exception as e:
        print(f"Error saving report: {e}")
        return False

def detect_hash_type(hash_string):
    """Try to detect the hash type based on format and length"""
    hash_string = hash_string.strip()
    
    # Check for Linux/Unix style hashes
    if hash_string.startswith('$1$'):
        return 'md5_crypt'
    elif hash_string.startswith('$2a$') or hash_string.startswith('$2b$'):
        return 'bcrypt'
    elif hash_string.startswith('$5$'):
        return 'sha256_crypt'
    elif hash_string.startswith('$6$'):
        return 'sha512_crypt'
    
    # Check by length for common hash types
    hash_length = len(hash_string)
    
    if hash_length == 32:
        return 'md5'
    elif hash_length == 40:
        return 'sha1'
    elif hash_length == 64:
        return 'sha256'
    elif hash_length == 128:
        return 'sha512'
    
    # Default
    return None

def main():
    parser = argparse.ArgumentParser(description='Educational Password Hash Comparison Tool')
    parser.add_argument('-H', '--hash', help='Single hash to compare')
    parser.add_argument('-f', '--hash-file', help='File containing hashes (one per line)')
    parser.add_argument('-w', '--wordlist', required=True, help='Path to wordlist file')
    parser.add_argument('-a', '--algorithm', 
                        choices=['md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'sha3_512', 
                                'ntlm', 'lm', 'bcrypt', 'md5_crypt', 'sha256_crypt', 'sha512_crypt', 'auto'], 
                        default='auto', help='Hashing algorithm to use (auto for detection)')
    parser.add_argument('-o', '--output', help='Output file for results (CSV format)')
    
    args = parser.parse_args()
    
    print_banner()
    
    if not args.hash and not args.hash_file:
        print("Error: You must provide either a hash (-H) or a hash file (-f)")
        return
    
    if not os.path.exists(args.wordlist):
        print(f"Error: Wordlist file not found: {args.wordlist}")
        return
    
    output_file = args.output or f"hash_comparison_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    # Check for required modules based on algorithm
    if args.algorithm in ['bcrypt'] and not BCRYPT_AVAILABLE:
        print(f"Error: {args.algorithm} requires the bcrypt module. Install with 'pip install bcrypt'")
        return
        
    if args.algorithm in ['ntlm', 'lm', 'md5_crypt', 'sha256_crypt', 'sha512_crypt'] and not PASSLIB_AVAILABLE:
        print(f"Error: {args.algorithm} requires the passlib module. Install with 'pip install passlib'")
        return
    
    results = []
    
    if args.hash:
        target_hash = args.hash.strip()
        algorithm = args.algorithm
        
        # Auto-detect hash type if requested
        if algorithm == 'auto':
            detected_algorithm = detect_hash_type(target_hash)
            if detected_algorithm:
                algorithm = detected_algorithm
                print(f"Auto-detected hash type: {algorithm}")
            else:
                print("Could not auto-detect hash type. Defaulting to MD5.")
                algorithm = 'md5'
        
        print(f"Comparing single hash: {target_hash}")
        print(f"Using algorithm: {algorithm}")
        print(f"Wordlist: {args.wordlist}")
        
        result = compare_hash(target_hash, args.wordlist, algorithm)
        result["hash"] = target_hash
        results.append(result)
    
    elif args.hash_file:
        if not os.path.exists(args.hash_file):
            print(f"Error: Hash file not found: {args.hash_file}")
            return
        
        print(f"Processing hash file: {args.hash_file}")
        print(f"Using algorithm: {args.algorithm}")
        print(f"Wordlist: {args.wordlist}")
        
        results = process_hash_file(args.hash_file, args.wordlist, args.algorithm)
    
    # Display results
    found_count = sum(1 for r in results if r.get("found", False))
    print(f"\nResults Summary: Found {found_count} out of {len(results)} hashes")
    
    for i, result in enumerate(results):
        if result.get("found", False):
            print(f"Hash {i+1}: {result.get('hash')} = '{result.get('original')}' "
                  f"(found in {result.get('time_taken'):.2f} seconds, "
                  f"checked {result.get('words_checked')} words)")
        else:
            print(f"Hash {i+1}: {result.get('hash')} - Not found "
                  f"(searched for {result.get('time_taken'):.2f} seconds, "
                  f"checked {result.get('words_checked')} words)")
    
    # Save report
    save_report(results, output_file)

if __name__ == "__main__":
    main()
