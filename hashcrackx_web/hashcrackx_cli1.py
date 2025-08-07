import hashlib
import itertools
import string
from multiprocessing import Pool, cpu_count, Value, Lock
from passlib.hash import bcrypt, sha512_crypt, scrypt, argon2
import time
import threading

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
        with lock:
            counter.value += 1
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

def run_crack(params):
    global start_time_global, counter

    target_hash = params.get('target_hash')
    hash_type = params.get('hash_type') or detect_hash_type(target_hash)
    min_length = params.get('min_length', 1)
    max_length = params.get('max_length', 4)
    characters = params.get('characters', string.ascii_letters + string.digits)
    max_workers = params.get('max_workers', cpu_count())
    use_wordlist = params.get('use_wordlist', False)
    wordlist_path = params.get('wordlist_path')
    save_output = params.get('save_output')

    counter = Value('i', 0)

    if not hash_type:
        return { 'status': 'error', 'message': 'Could not detect hash type.' }

    password_source = get_passwords_from_file(wordlist_path) if use_wordlist else generate_passwords(min_length, max_length, characters)

    start_time_global = time.time()
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
            return { 'status': 'error', 'message': str(e) }

    elapsed_time = time.time() - start_time_global

    if found_password:
        if save_output:
            save_result(found_password, save_output)
        return {
            'status': 'success',
            'password': found_password,
            'attempts': counter.value,
            'time': round(elapsed_time, 2)
        }
    else:
        return {
            'status': 'fail',
            'message': 'Password not found.',
            'attempts': counter.value,
            'time': round(elapsed_time, 2)
        }

