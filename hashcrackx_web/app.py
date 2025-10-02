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
socketio = SocketIO(app, async_mode='threading')

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

CHARSET_MAP = {
    "numeric": string.digits,
    "alpha": string.ascii_letters,
    "alphanumeric": string.ascii_letters + string.digits,
    "all": string.ascii_letters + string.digits + string.punctuation
}

def detect_hash_type(hash_str):
    length = len(hash_str)
    return {
        32: 'md5',
        40: 'sha1',
        56: 'sha224',
        64: 'sha256',
        96: 'sha384',
        128: 'sha512'
    }.get(length, 'md5')

def compute_hash(hash_type, text):
    return getattr(hashlib, hash_type)(text.encode()).hexdigest()

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

def brute_force(hash_input, hash_type, charset, min_len, max_len):
    emit_log("[*] Starting brute-force...")
    start_time = time.time()
    stop_event = threading.Event()
    threading.Thread(target=start_timer, args=(start_time, stop_event)).start()

    total_combinations = sum(len(charset) ** i for i in range(min_len, max_len + 1))
    current = 0

    for length in range(min_len, max_len + 1):
        for attempt in itertools.product(charset, repeat=length):
            guess = ''.join(attempt)
            hashed = compute_hash(hash_type, guess)
            current += 1
            progress = int((current / total_combinations) * 100)
            emit_progress(progress)
            if hashed == hash_input:
                stop_event.set()
                emit_cracked(f"✅ Password found: {guess}")
                emit_log(f"[+] Cracked: {guess}")
                return
    stop_event.set()
    emit_cracked("❌ Password not found using brute-force.")
    emit_log("[!] Password not found using brute-force.")

def wordlist_attack(hash_input, hash_type, wordlist_path):
    emit_log("[*] Starting wordlist attack...")
    start_time = time.time()
    stop_event = threading.Event()
    threading.Thread(target=start_timer, args=(start_time, stop_event)).start()

    try:
        with open(wordlist_path, 'r', errors='ignore') as file:
            lines = file.readlines()

        total = len(lines)
        for i, line in enumerate(lines):
            guess = line.strip()
            hashed = compute_hash(hash_type, guess)
            progress = int(((i+1)/total) * 100)
            emit_progress(progress)
            if hashed == hash_input:
                stop_event.set()
                emit_cracked(f"✅ Password found: {guess}")
                emit_log(f"[+] Cracked: {guess}")
                return
    except Exception as e:
        emit_log(f"[!] Error: {str(e)}")
        stop_event.set()
        return

    stop_event.set()
    emit_cracked("❌ Password not found using wordlist.")
    emit_log("[!] Password not found using wordlist.")

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('start_crack')
def handle_crack(data):
    hash_input = data['hash']
    hash_type = data['hash_type'] or detect_hash_type(hash_input)
    mode = data['mode']

    emit_log(f"[*] Auto-detected hash type: {hash_type}")

    if mode == 'brute':
        charset_key = data['charset']
        min_len = int(data['min_length'])
        max_len = int(data['max_length'])
        charset = CHARSET_MAP.get(charset_key, string.ascii_lowercase)
        threading.Thread(target=brute_force, args=(hash_input, hash_type, charset, min_len, max_len)).start()

    elif mode == 'wordlist':
        wordlist_file = data['wordlist_file']
        threading.Thread(target=wordlist_attack, args=(hash_input, hash_type, wordlist_file)).start()

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'wordlist' not in request.files:
        return {"error": "No file part"}, 400

    file = request.files['wordlist']
    if file.filename == '' or not allowed_file(file.filename):
        return {"error": "Invalid file"}, 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    return {"success": True, "path": filepath}, 200

if __name__ == '__main__':
    print("🚀 Visit the app at: http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True, debug=True)

