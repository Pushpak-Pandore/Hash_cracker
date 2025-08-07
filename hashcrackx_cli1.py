import argparse
import hashlib
import itertools
import string
from multiprocessing import Pool, cpu_count, Value, Lock
from passlib.hash import bcrypt, sha512_crypt, scrypt, argon2
import sys
import time
import threading
import os

HASH_LENGTH_MAP = {
    32: 'md5',
    40: 'sha1',
    56: 'sha224',
    64: 'sha256',
    96: 'sha384',
    128: 'sha512',
}

ADVANCED_HASHES = {
    'bcrypt': bcrypt,
    'scrypt': scrypt,
    'argon2': argon2,
    'sha512_crypt': sha512_crypt
}

COMMON_HASHES = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha224': hashlib.sha224,
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512,
    'sha3_224': hashlib.sha3_224,
    'sha3_256': hashlib.sha3_256,
    'sha3_384': hashlib.sha3_384,
    'sha3_512': hashlib.sha3_512
}

counter = Value('i', 0)
lock = Lock()
start_time_global = time.time()
speed_history = []

def live_counter():
    while True:
        with lock:
            count = counter.value
        elapsed = time.time() - start_time_global
        rate = count / elapsed if elapsed > 0 else 0
        sys.stdout.write(f"\r[*] Tried: {count:,} passwords | Speed: {rate:.1f} pwd/s     ")
        sys.stdout.flush()
        time.sleep(1)

def detect_hash_type(hash_str: str):
    return HASH_LENGTH_MAP.get(len(hash_str))

def generate_passwords(min_len, max_len, charset):
    for length in range(min_len, max_len + 1):
        for pwd in itertools.product(charset, repeat=length):
            yield ''.join(pwd)

def get_passwords_from_file(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]

def check_hash_mp(args):
    hash_fn, password, target_hash = args
    try:
        result = hash_fn(password.encode()).hexdigest() == target_hash
        try:
            with lock:
                counter.value += 1
        except:
            pass
        return password if result else None
    except Exception:
        return None

def check_advanced_hash(hash_fn, password, target_hash):
    try:
        with lock:
            counter.value += 1
        return hash_fn.verify(password, target_hash)
    except:
        return False

def save_result(password, output_file):
    try:
        with open(output_file, 'w') as f:
            f.write(f"Password: {password}\n")
    except Exception as e:
        print(f"[!] Error saving result: {e}")

def crack_hash(target_hash, hash_type=None, min_length=1, max_length=4, characters=string.ascii_letters + string.digits, max_workers=cpu_count(), use_wordlist=False, wordlist_path=None, save_output=None):
    global start_time_global

    print("\n 🧠⚡ Welcome to HashCrackX")
    print("👨‍💻 Created by: Pushpak Pandore")
    print("-----------------------------------------------")

    hash_type = hash_type or detect_hash_type(target_hash)
    if not hash_type:
        print("[!] Could not detect hash type.")
        return None

    print(f"[*] Cracking {target_hash} using type {hash_type}")

    if use_wordlist and not wordlist_path:
        print("[!] Wordlist option enabled but no file provided.")
        return None

    password_source = get_passwords_from_file(wordlist_path) if use_wordlist else generate_passwords(min_length, max_length, characters)

    if use_wordlist:
        print(f"[i] Loaded {len(password_source)} passwords.")
        print(f"[i] First few passwords: {password_source[:5]}")

    start_time_global = time.time()
    live_thread = threading.Thread(target=live_counter, daemon=True)
    live_thread.start()

    found_password = None

    if hash_type in ADVANCED_HASHES:
        hash_fn = ADVANCED_HASHES[hash_type]
        for pwd in password_source:
            if check_advanced_hash(hash_fn, pwd, target_hash):
                found_password = pwd
                break
    elif hash_type in COMMON_HASHES:
        hash_fn = COMMON_HASHES[hash_type]
        try:
            with Pool(processes=max_workers) as pool:
                args = ((hash_fn, pwd, target_hash) for pwd in password_source)
                for result in pool.imap_unordered(check_hash_mp, args, chunksize=500):
                    if result:
                        found_password = result
                        pool.terminate()
                        break
                pool.close()
                pool.join()
        except Exception as e:
            print(f"\n[!] Error during cracking: {e}")

    print()  # ensure next print starts on new line
    if found_password:
        print(f"[+] Password found: {found_password}")
        print(f"[i] Total tried: {counter.value}")
        print(f"[i] Time elapsed: {time.time() - start_time_global:.2f} seconds")
        if save_output:
            save_result(found_password, save_output)
        return found_password
    else:
        print("[!] Password not found.")
        print(f"[i] Total tried: {counter.value}")
        print(f"[i] Time elapsed: {time.time() - start_time_global:.2f} seconds")
        return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="HashCrackX CLI Tool")
    parser.add_argument('--hash', required=True, help='Target hash to crack')
    parser.add_argument('--hash-type', help='Type of hash (e.g. md5, sha256)')
    parser.add_argument('--min-length', type=int, default=1, help='Minimum password length')
    parser.add_argument('--max-length', type=int, default=4, help='Maximum password length')
    parser.add_argument('--characters', default=string.ascii_letters + string.digits, help='Characters to use in brute-force')
    parser.add_argument('--max-workers', type=int, default=cpu_count(), help='Number of processes')
    parser.add_argument('--use-wordlist', action='store_true', help='Use a wordlist instead of brute-force')
    parser.add_argument('--wordlist', help='Path to wordlist file')
    parser.add_argument('--save-output', help='Save cracked password to file')

    args = parser.parse_args()

    crack_hash(
        target_hash=args.hash,
        hash_type=args.hash_type,
        min_length=args.min_length,
        max_length=args.max_length,
        characters=args.characters,
        max_workers=args.max_workers,
        use_wordlist=args.use_wordlist,
        wordlist_path=args.wordlist,
        save_output=args.save_output
    )

