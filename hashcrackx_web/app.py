"""from flask import Flask, render_template, request
from flask_socketio import SocketIO
import hashlib
import itertools
import string
import os
import threading
from werkzeug.utils import secure_filename

# Flask app setup
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Enable async with eventlet
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Supported hash functions
HASH_FUNCTIONS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha224': hashlib.sha224,
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512
}

def auto_detect_hash_type(hash_value):
    length_map = {
        32: 'md5',
        40: 'sha1',
        56: 'sha224',
        64: 'sha256',
        96: 'sha384',
        128: 'sha512'
    }
    return length_map.get(len(hash_value))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/crack', methods=['POST'])
def crack():
    hash_input = request.form['hash']
    hash_type = request.form['hashType']
    use_wordlist = 'useWordlist' in request.form

    min_length = int(request.form.get('minLength', 1))
    max_length = int(request.form.get('maxLength', 4))
    characters = request.form.get('characters', string.ascii_letters + string.digits)

    if not hash_type:
        hash_type = auto_detect_hash_type(hash_input)
        if hash_type:
            socketio.emit('log', {'data': f'[*] Auto-detected hash type: {hash_type}'})
        else:
            socketio.emit('log', {'data': '[!] Could not auto-detect hash type.'})
            return '', 400

    wordlist_path = None
    if use_wordlist and 'wordlistFile' in request.files:
        wordlist = request.files['wordlistFile']
        if wordlist.filename:
            filename = secure_filename(wordlist.filename)
            wordlist_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            wordlist.save(wordlist_path)

    threading.Thread(target=run_cracker, args=(
        hash_input, hash_type, use_wordlist,
        wordlist_path, min_length, max_length, characters
    )).start()
    return '', 204

def run_cracker(target_hash, hash_type, use_wordlist, wordlist_path, min_length, max_length, characters):
    try:
        hash_func = HASH_FUNCTIONS.get(hash_type)
        if not hash_func:
            socketio.emit('log', {'data': '[!] Unsupported hash type.'})
            return

        if use_wordlist and wordlist_path:
            socketio.emit('log', {'data': '[*] Using wordlist...'})
            try:
                with open(wordlist_path, 'r', errors='ignore') as f:
                    for line in f:
                        password = line.strip()
                        hashed = hash_func(password.encode()).hexdigest()
                        if hashed == target_hash:
                            socketio.emit('log', {'data': f'✅ Password found: {password}'})
                            return
                socketio.emit('log', {'data': '[!] Password not found in wordlist.'})
            except Exception as e:
                socketio.emit('log', {'data': f'[!] Error reading wordlist: {e}'})
            finally:
                try:
                    os.remove(wordlist_path)
                except:
                    pass
        else:
            socketio.emit('log', {'data': '[*] Starting brute-force...'})
            for length in range(min_length, max_length + 1):
                for combo in itertools.product(characters, repeat=length):
                    password = ''.join(combo)
                    hashed = hash_func(password.encode()).hexdigest()
                    if hashed == target_hash:
                        socketio.emit('log', {'data': f'✅ Password found: {password}'})
                        return
            socketio.emit('log', {'data': '[!] Password not found using brute-force.'})
    except Exception as e:
        socketio.emit('log', {'data': f'[!] Internal Error: {e}'})

if __name__ == '__main__':
    import eventlet
    eventlet.monkey_patch()  # VERY IMPORTANT
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)}"""


"""from flask import Flask, render_template, request
from flask_socketio import SocketIO
import hashlib
import itertools
import string
import os
import threading
from werkzeug.utils import secure_filename

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

HASH_FUNCTIONS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha224': hashlib.sha224,
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512
}

def auto_detect_hash_type(hash_value):
    length_map = {
        32: 'md5',
        40: 'sha1',
        56: 'sha224',
        64: 'sha256',
        96: 'sha384',
        128: 'sha512'
    }
    return length_map.get(len(hash_value))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/crack', methods=['POST'])
def crack():
    hash_input = request.form['hash']
    hash_type = request.form['hashType']
    use_wordlist = 'useWordlist' in request.form

    min_length = int(request.form.get('minLength', 1))
    max_length = int(request.form.get('maxLength', 4))
    characters = request.form.get('characters', string.ascii_letters + string.digits)

    if not hash_type:
        hash_type = auto_detect_hash_type(hash_input)
        if hash_type:
            socketio.emit('log', {'data': f'[*] Auto-detected hash type: {hash_type}'}, namespace='/')
        else:
            socketio.emit('log', {'data': '[!] Could not auto-detect hash type.'}, namespace='/')
            return '', 400

    wordlist_path = None
    if use_wordlist and 'wordlistFile' in request.files:
        wordlist = request.files['wordlistFile']
        if wordlist.filename:
            filename = secure_filename(wordlist.filename)
            wordlist_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            wordlist.save(wordlist_path)

    threading.Thread(target=run_cracker, args=(
        hash_input, hash_type, use_wordlist, wordlist_path, min_length, max_length, characters)).start()
    return '', 204

def run_cracker(target_hash, hash_type, use_wordlist, wordlist_path, min_length, max_length, characters):
    try:
        if use_wordlist and wordlist_path:
            socketio.emit('log', {'data': '[*] Using uploaded wordlist...'}, namespace='/')
            try:
                with open(wordlist_path, 'r', errors='ignore') as f:
                    for line in f:
                        password = line.strip()
                        hash_func = HASH_FUNCTIONS.get(hash_type)
                        if not hash_func:
                            socketio.emit('log', {'data': '[!] Unsupported hash type.'}, namespace='/')
                            return
                        hashed = hash_func(password.encode()).hexdigest()
                        if hashed == target_hash:
                            socketio.emit('log', {'data': f'✅ Password found: {password}'}, namespace='/')
                            return
                socketio.emit('log', {'data': '[!] Password not found in wordlist.'}, namespace='/')
            except Exception as e:
                socketio.emit('log', {'data': f'[!] Error reading wordlist: {e}'}, namespace='/')
            finally:
                try:
                    os.remove(wordlist_path)
                except:
                    pass
        else:
            socketio.emit('log', {'data': '[*] Starting brute-force...'}, namespace='/')
            for length in range(min_length, max_length + 1):
                for combo in itertools.product(characters, repeat=length):
                    password = ''.join(combo)
                    hash_func = HASH_FUNCTIONS.get(hash_type)
                    if not hash_func:
                        socketio.emit('log', {'data': '[!] Unsupported hash type.'}, namespace='/')
                        return
                    hashed = hash_func(password.encode()).hexdigest()
                    if hashed == target_hash:
                        socketio.emit('log', {'data': f'✅ Password found: {password}'}, namespace='/')
                        return
            socketio.emit('log', {'data': '[!] Password not found using brute-force.'}, namespace='/')
    except Exception as e:
        socketio.emit('log', {'data': f'[!] Internal Error: {e}'}, namespace='/')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False)"""
    
    
from flask import Flask, render_template, request, session
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
import os
import time
import hashlib
import threading
import string
import itertools
import multiprocessing
import bcrypt
import scrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, HashingError
import queue
import math
from datetime import datetime, timedelta
import secrets

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Global variables for managing cracking sessions
active_sessions = {}
session_results = {}

CHARSET_MAP = {
    "numeric": string.digits,
    "alpha": string.ascii_letters,
    "alphanumeric": string.ascii_letters + string.digits,
    "all": string.ascii_letters + string.digits + string.punctuation,
    "lowercase": string.ascii_lowercase,
    "uppercase": string.ascii_uppercase,
    "hex": "0123456789abcdef"
}

# Enhanced hash type detection
HASH_FUNCTIONS = {
    'md5': lambda x: hashlib.md5(x.encode()).hexdigest(),
    'sha1': lambda x: hashlib.sha1(x.encode()).hexdigest(),
    'sha224': lambda x: hashlib.sha224(x.encode()).hexdigest(),
    'sha256': lambda x: hashlib.sha256(x.encode()).hexdigest(),
    'sha384': lambda x: hashlib.sha384(x.encode()).hexdigest(),
    'sha512': lambda x: hashlib.sha512(x.encode()).hexdigest(),
    'sha3_224': lambda x: hashlib.sha3_224(x.encode()).hexdigest(),
    'sha3_256': lambda x: hashlib.sha3_256(x.encode()).hexdigest(),
    'sha3_384': lambda x: hashlib.sha3_384(x.encode()).hexdigest(),
    'sha3_512': lambda x: hashlib.sha3_512(x.encode()).hexdigest(),
}

def detect_hash_type(hash_str):
    """Enhanced hash type detection with better accuracy"""
    length = len(hash_str.strip())
    
    # Check for specific hash patterns first
    if hash_str.startswith('$2a$') or hash_str.startswith('$2b$') or hash_str.startswith('$2y$'):
        return 'bcrypt'
    elif hash_str.startswith('$argon2'):
        return 'argon2'
    elif hash_str.startswith('$7$'):
        return 'scrypt'
    
    # Standard length-based detection
    length_map = {
        32: 'md5',
        40: 'sha1', 
        56: 'sha224',
        64: 'sha256',
        96: 'sha384',
        128: 'sha512'
    }
    
    detected_type = length_map.get(length, 'md5')
    
    # Additional validation for hex strings
    if length in [32, 40, 56, 64, 96, 128]:
        try:
            int(hash_str, 16)  # Validate it's a valid hex string
            return detected_type
        except ValueError:
            return 'unknown'
    
    return detected_type

def compute_hash(hash_type, text, salt=None):
    """Enhanced hash computation with support for advanced hash types"""
    try:
        if hash_type == 'bcrypt':
            if salt:
                return bcrypt.hashpw(text.encode(), salt).decode()
            return None  # bcrypt needs salt for verification
        elif hash_type == 'scrypt':
            if scrypt and salt:
                return scrypt.hash(text, salt).hex()
            return None
        elif hash_type == 'argon2':
            if salt:
                ph = PasswordHasher()
                return ph.hash(text)
            return None
        elif hash_type in HASH_FUNCTIONS:
            return HASH_FUNCTIONS[hash_type](text)
        else:
            # Fallback to hashlib
            return getattr(hashlib, hash_type)(text.encode()).hexdigest()
    except Exception as e:
        emit_log(f"[!] Hash computation error: {e}")
        return None

def verify_hash(hash_type, text, target_hash):
    """Verify hash with support for salted hashes"""
    try:
        if hash_type == 'bcrypt':
            return bcrypt.checkpw(text.encode(), target_hash.encode())
        elif hash_type == 'argon2':
            ph = PasswordHasher()
            try:
                ph.verify(target_hash, text)
                return True
            except (VerifyMismatchError, HashingError):
                return False
        elif hash_type == 'scrypt':
            # Scrypt verification is more complex, skip for now  
            if scrypt:
                # TODO: Implement scrypt verification with proper salt handling
                pass
            return False
        else:
            computed = compute_hash(hash_type, text)
            return computed == target_hash.lower()
    except Exception:
        return False

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def emit_log(msg):
    socketio.emit('log', {'message': msg})

def emit_progress(progress):
    socketio.emit('progress', {'percent': progress})

def emit_cracked(result):
    socketio.emit('cracked', {'result': result})

def emit_timer(elapsed):
    socketio.emit('timer', {'elapsed': elapsed})

def start_timer(start_time, stop_event):
    while not stop_event.is_set():
        elapsed = int(time.time() - start_time)
        emit_timer(elapsed)
        time.sleep(1)

def brute_force_worker(args):
    """Worker function for multiprocessing brute force"""
    charset, length, start_idx, end_idx, hash_type, target_hash = args
    
    for i in range(start_idx, min(end_idx, len(charset) ** length)):
        # Convert index to combination
        temp = i
        combo = []
        for _ in range(length):
            combo.append(charset[temp % len(charset)])
            temp //= len(charset)
        
        password = ''.join(reversed(combo))
        
        if verify_hash(hash_type, password, target_hash):
            return password
    return None

def calculate_combinations(charset_len, min_len, max_len):
    """Calculate total combinations for progress estimation"""
    total = 0
    for length in range(min_len, max_len + 1):
        total += charset_len ** length
    return total

def estimate_time(combinations, charset_len):
    """Estimate cracking time based on complexity"""
    # Rough estimates based on hash type and combinations
    base_rate = 1000000  # hashes per second (conservative estimate)
    seconds = combinations / base_rate
    
    if seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds/60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds/3600)} hours"
    else:
        return f"{int(seconds/86400)} days"

def brute_force(hash_input, hash_type, charset, min_len, max_len, session_id=None):
    """Enhanced multiprocessing brute force with better progress estimation"""
    emit_log("[*] Starting enhanced brute-force attack...")
    emit_log(f"[*] Hash type: {hash_type}")
    emit_log(f"[*] Character set: {len(charset)} characters")
    emit_log(f"[*] Length range: {min_len}-{max_len}")
    
    start_time = time.time()
    stop_event = threading.Event()
    timer_thread = threading.Thread(target=start_timer, args=(start_time, stop_event))
    timer_thread.start()

    total_combinations = calculate_combinations(len(charset), min_len, max_len)
    emit_log(f"[*] Total combinations: {total_combinations:,}")
    emit_log(f"[*] Estimated time: {estimate_time(total_combinations, len(charset))}")
    
    # Use multiprocessing for better performance
    cpu_count = multiprocessing.cpu_count()
    chunk_size = max(1000, total_combinations // (cpu_count * 10))
    
    emit_log(f"[*] Using {cpu_count} CPU cores")
    
    current_progress = 0
    
    # Process each length separately for better progress tracking
    for length in range(min_len, max_len + 1):
        length_combinations = len(charset) ** length
        emit_log(f"[*] Processing length {length} ({length_combinations:,} combinations)...")
        
        # Split work into chunks for multiprocessing
        chunks = []
        for i in range(0, length_combinations, chunk_size):
            end_idx = min(i + chunk_size, length_combinations)
            chunks.append((charset, length, i, end_idx, hash_type, hash_input))
        
        # Process chunks in batches to avoid memory issues
        batch_size = cpu_count * 2
        
        with multiprocessing.Pool(processes=cpu_count) as pool:
            for batch_start in range(0, len(chunks), batch_size):
                batch_end = min(batch_start + batch_size, len(chunks))
                batch_chunks = chunks[batch_start:batch_end]
                
                try:
                    results = pool.map(brute_force_worker, batch_chunks)
                    
                    # Check results
                    for result in results:
                        if result:
                            stop_event.set()
                            pool.terminate()
                            timer_thread.join(timeout=1)
                            emit_cracked(f"✅ Password found: {result}")
                            emit_log(f"[+] Password cracked: {result}")
                            emit_log(f"[+] Time taken: {time.time() - start_time:.2f} seconds")
                            return
                    
                    # Update progress
                    processed_chunks = min(batch_end, len(chunks))
                    length_progress = (processed_chunks / len(chunks)) * 100
                    
                    # Calculate overall progress
                    lengths_completed = length - min_len
                    total_lengths = max_len - min_len + 1
                    overall_progress = ((lengths_completed / total_lengths) + 
                                     (length_progress / 100) / total_lengths) * 100
                    
                    emit_progress(min(int(overall_progress), 99))
                    
                    if processed_chunks % 5 == 0:  # Update every 5 chunks
                        elapsed = time.time() - start_time
                        rate = (current_progress * total_combinations / 100) / elapsed if elapsed > 0 else 0
                        emit_log(f"[*] Progress: {overall_progress:.1f}% (Rate: {rate:.0f} h/s)")
                        
                except Exception as e:
                    emit_log(f"[!] Multiprocessing error: {e}")
                    # Fallback to single-threaded
                    break
    
    stop_event.set()
    timer_thread.join(timeout=1)
    emit_cracked("❌ Password not found using brute-force.")
    emit_log("[!] Password not found using brute-force.")
    emit_log(f"[!] Total time: {time.time() - start_time:.2f} seconds")

def wordlist_attack_worker(args):
    """Worker function for multiprocessing wordlist attack"""
    words_chunk, hash_type, target_hash = args
    
    for word in words_chunk:
        word = word.strip()
        if not word:
            continue
            
        if verify_hash(hash_type, word, target_hash):
            return word
    return None

def wordlist_attack(hash_input, hash_type, wordlist_path, session_id=None):
    """Enhanced multiprocessing wordlist attack"""
    emit_log("[*] Starting enhanced wordlist attack...")
    emit_log(f"[*] Hash type: {hash_type}")
    emit_log(f"[*] Wordlist: {os.path.basename(wordlist_path)}")
    
    start_time = time.time()
    stop_event = threading.Event()
    timer_thread = threading.Thread(target=start_timer, args=(start_time, stop_event))
    timer_thread.start()

    try:
        # Read and preprocess wordlist
        with open(wordlist_path, 'r', errors='ignore', encoding='utf-8') as file:
            words = [line.strip() for line in file if line.strip()]
        
        total_words = len(words)
        emit_log(f"[*] Loaded {total_words:,} words from wordlist")
        
        if total_words == 0:
            emit_log("[!] Empty wordlist!")
            stop_event.set()
            timer_thread.join(timeout=1)
            return
        
        # Use multiprocessing for better performance
        cpu_count = multiprocessing.cpu_count()
        chunk_size = max(100, total_words // (cpu_count * 4))
        
        emit_log(f"[*] Using {cpu_count} CPU cores")
        emit_log(f"[*] Processing in chunks of {chunk_size} words")
        
        # Split words into chunks
        chunks = []
        for i in range(0, total_words, chunk_size):
            word_chunk = words[i:i + chunk_size]
            chunks.append((word_chunk, hash_type, hash_input))
        
        # Process chunks with multiprocessing
        processed_words = 0
        
        with multiprocessing.Pool(processes=cpu_count) as pool:
            # Process in batches to manage memory
            batch_size = cpu_count * 2
            
            for batch_start in range(0, len(chunks), batch_size):
                batch_end = min(batch_start + batch_size, len(chunks))
                batch_chunks = chunks[batch_start:batch_end]
                
                try:
                    results = pool.map(wordlist_attack_worker, batch_chunks)
                    
                    # Check results
                    for result in results:
                        if result:
                            stop_event.set()
                            pool.terminate()
                            timer_thread.join(timeout=1)
                            emit_cracked(f"✅ Password found: {result}")
                            emit_log(f"[+] Password cracked: {result}")
                            emit_log(f"[+] Time taken: {time.time() - start_time:.2f} seconds")
                            
                            # Cleanup wordlist file
                            try:
                                os.remove(wordlist_path)
                                emit_log("[*] Wordlist file cleaned up")
                            except:
                                pass
                            return
                    
                    # Update progress
                    processed_chunks = min(batch_end, len(chunks))
                    processed_words = processed_chunks * chunk_size
                    progress = min(int((processed_words / total_words) * 100), 99)
                    emit_progress(progress)
                    
                    if processed_chunks % 5 == 0:  # Log every 5 batches
                        elapsed = time.time() - start_time
                        rate = processed_words / elapsed if elapsed > 0 else 0
                        emit_log(f"[*] Progress: {progress}% ({processed_words:,}/{total_words:,} words, {rate:.0f} w/s)")
                        
                except Exception as e:
                    emit_log(f"[!] Multiprocessing error: {e}")
                    # Fallback to single-threaded processing
                    emit_log("[*] Falling back to single-threaded processing...")
                    
                    for word in words[processed_words:]:
                        word = word.strip()
                        if not word:
                            continue
                            
                        if verify_hash(hash_type, word, hash_input):
                            stop_event.set()
                            timer_thread.join(timeout=1)
                            emit_cracked(f"✅ Password found: {word}")
                            emit_log(f"[+] Password cracked: {word}")
                            
                            # Cleanup
                            try:
                                os.remove(wordlist_path)
                            except:
                                pass
                            return
                        
                        processed_words += 1
                        if processed_words % 1000 == 0:
                            progress = int((processed_words / total_words) * 100)
                            emit_progress(progress)
                    break
        
        stop_event.set()
        timer_thread.join(timeout=1)
        emit_cracked("❌ Password not found in wordlist.")
        emit_log("[!] Password not found in wordlist.")
        emit_log(f"[!] Checked {total_words:,} passwords in {time.time() - start_time:.2f} seconds")
        
    except Exception as e:
        emit_log(f"[!] Wordlist attack error: {str(e)}")
        stop_event.set()
        timer_thread.join(timeout=1)
    
    # Cleanup wordlist file
    try:
        os.remove(wordlist_path)
        emit_log("[*] Wordlist file cleaned up")
    except:
        pass

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('start_crack')
def handle_crack(data):
    """Enhanced crack handler with session management and rate limiting"""
    
    # Generate session ID for tracking
    session_id = secrets.token_hex(8)
    client_id = request.sid
    
    # Rate limiting check (max 3 concurrent sessions per IP)
    client_sessions = [s for s in active_sessions.values() if s.get('client_id') == client_id]
    if len(client_sessions) >= 3:
        emit_log("[!] Rate limit exceeded. Maximum 3 concurrent sessions allowed.")
        emit_cracked("❌ Rate limit exceeded. Please wait for current sessions to complete.")
        return
    
    hash_input = data.get('hash', '').strip()
    hash_type = data.get('hash_type', '') or detect_hash_type(hash_input)
    mode = data.get('mode', '')
    
    # Validation
    if not hash_input:
        emit_log("[!] Error: No hash provided")
        emit_cracked("❌ Please enter a hash to crack")
        return
    
    if not mode:
        emit_log("[!] Error: No cracking mode specified")
        emit_cracked("❌ Please select a cracking mode")
        return
    
    # Store session info
    active_sessions[session_id] = {
        'client_id': client_id,
        'hash': hash_input,
        'hash_type': hash_type,
        'mode': mode,
        'start_time': datetime.now(),
        'status': 'running'
    }
    
    emit_log(f"[*] Session ID: {session_id}")
    emit_log(f"[*] Hash: {hash_input[:20]}{'...' if len(hash_input) > 20 else ''}")
    emit_log(f"[*] Detected hash type: {hash_type}")
    emit_log(f"[*] Mode: {mode}")

    if mode == 'brute':
        charset_key = data.get('charset', 'alphanumeric')
        min_len = int(data.get('min_length', 1))
        max_len = int(data.get('max_length', 4))
        
        # Validation for brute force
        if max_len > 8:
            emit_log("[!] Warning: Maximum length limited to 8 for performance")
            max_len = 8
        
        if min_len > max_len:
            emit_log("[!] Error: Minimum length cannot be greater than maximum length")
            emit_cracked("❌ Invalid length parameters")
            del active_sessions[session_id]
            return
        
        charset = CHARSET_MAP.get(charset_key, string.ascii_lowercase + string.digits)
        
        # Start brute force in separate thread
        crack_thread = threading.Thread(
            target=brute_force, 
            args=(hash_input, hash_type, charset, min_len, max_len, session_id)
        )
        crack_thread.daemon = True
        crack_thread.start()

    elif mode == 'wordlist':
        wordlist_file = data.get('wordlist_file')
        
        if not wordlist_file or not os.path.exists(wordlist_file):
            emit_log("[!] Error: Wordlist file not found")
            emit_cracked("❌ Please upload a valid wordlist file")
            del active_sessions[session_id]
            return
        
        # Check file size
        file_size = os.path.getsize(wordlist_file)
        if file_size > 50 * 1024 * 1024:  # 50MB limit
            emit_log("[!] Error: Wordlist file too large (max 50MB)")
            emit_cracked("❌ Wordlist file is too large")
            del active_sessions[session_id]
            return
        
        # Start wordlist attack in separate thread
        crack_thread = threading.Thread(
            target=wordlist_attack, 
            args=(hash_input, hash_type, wordlist_file, session_id)
        )
        crack_thread.daemon = True
        crack_thread.start()
    
    else:
        emit_log(f"[!] Unknown mode: {mode}")
        emit_cracked("❌ Unknown cracking mode")
        del active_sessions[session_id]

@app.route('/upload', methods=['POST'])
def upload_file():
    """Enhanced file upload with better validation and security"""
    if 'wordlist' not in request.files:
        return {"error": "No file part"}, 400

    file = request.files['wordlist']
    if file.filename == '' or not allowed_file(file.filename):
        return {"error": "Invalid file type. Only .txt files are allowed."}, 400

    # Additional security checks
    if file.content_length and file.content_length > 50 * 1024 * 1024:  # 50MB limit
        return {"error": "File too large. Maximum size is 50MB."}, 400

    filename = secure_filename(file.filename)
    # Add timestamp to avoid conflicts
    timestamp = str(int(time.time()))
    filename = f"{timestamp}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        file.save(filepath)
        
        # Validate file content
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            first_lines = [f.readline() for _ in range(5)]  # Check first 5 lines
            if not any(line.strip() for line in first_lines):
                os.remove(filepath)
                return {"error": "File appears to be empty or invalid."}, 400
        
        return {"success": True, "path": filepath}, 200
        
    except Exception as e:
        return {"error": f"Upload failed: {str(e)}"}, 500

@app.route('/hash_info/<hash_value>')
def hash_info(hash_value):
    """Provide information about a hash"""
    hash_type = detect_hash_type(hash_value)
    length = len(hash_value.strip())
    
    info = {
        "hash": hash_value,
        "detected_type": hash_type,
        "length": length,
        "is_valid": hash_type != 'unknown',
        "supported": hash_type in ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'bcrypt', 'argon2']
    }
    
    return info

@app.route('/session_status')
def session_status():
    """Get status of active cracking sessions"""
    status = {
        "active_sessions": len(active_sessions),
        "sessions": []
    }
    
    for sid, session in active_sessions.items():
        session_info = {
            "id": sid,
            "hash_type": session.get('hash_type'),
            "mode": session.get('mode'),
            "duration": str(datetime.now() - session.get('start_time', datetime.now())),
            "status": session.get('status', 'unknown')
        }
        status["sessions"].append(session_info)
    
    return status

@app.route('/compare_hashes', methods=['POST'])
def compare_hashes():
    """Compare multiple hashes and detect types"""
    data = request.get_json()
    hashes = data.get('hashes', [])
    
    results = []
    for hash_value in hashes:
        hash_type = detect_hash_type(hash_value)
        results.append({
            "hash": hash_value,
            "type": hash_type,
            "length": len(hash_value.strip())
        })
    
    return {"results": results}

if __name__ == '__main__':
    print("🚀 Visit the app at: http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True, debug=True)

