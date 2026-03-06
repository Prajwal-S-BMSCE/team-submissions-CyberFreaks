from flask import Flask, render_template, request, jsonify
import json
import traceback
import secrets
import base64
import os
import time
from werkzeug.utils import secure_filename

# Import your from-scratch crypto implementations
import kyber
from chacha20 import ChaCha20
from sha3_from_scratch import shake256
from poly1305 import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt

# Initialize the Flask application
app = Flask(__name__)

# Configure upload settings
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'zip'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

def derive_locked_key(shared_secret, password):
    """
    Mixes the Kyber shared secret with a user-provided password/secret-key.
    If no password is provided, returns the original shared secret.
    """
    if not password:
        return shared_secret
    # Combine the post-quantum secret with the user password
    combined = shared_secret + password.encode('utf-8')
    # Derive a final 32-byte key for ChaCha20
    return shake256(combined, 32)

def truncate_data(data, limit=64):
    """Helper function to shorten long hex strings for display."""
    if isinstance(data, bytes):
        hex_data = data.hex()
        return hex_data[:limit] + '...' if len(hex_data) > limit else hex_data
    return f"Object of type {type(data).__name__}"

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Renders the main HTML page."""
    return render_template('index.html')

@app.route('/run_crypto', methods=['POST'])
def run_crypto():
    """
    This function is called by the JavaScript on the webpage.
    It runs the full Kyber+ChaCha20 hybrid encryption flow with performance metrics.
    """
    # Dictionary to store timings
    timings = {}
    
    try:
        # Get and validate input
        data = request.get_json()
        
        # VALIDATION 1: Check if data exists
        if not data:
            return jsonify({
                'status': 'Error',
                'message': 'No data received. Please send JSON data.'
            }), 400
        
        plaintext_str = data.get('plaintext', '')
        password = data.get('password', '')  # The user's Secret Key
        
        # VALIDATION 2: Check if plaintext is empty
        if not plaintext_str or not plaintext_str.strip():
            return jsonify({
                'status': 'Error',
                'message': 'Plaintext cannot be empty. Please enter a message.'
            }), 400
        
        # VALIDATION 3: Check length limits
        if len(plaintext_str) > 10000:  # 10KB limit
            return jsonify({
                'status': 'Error',
                'message': 'Message too long. Maximum 10,000 characters allowed.'
            }), 400
        
        # VALIDATION 4: Check for valid UTF-8 encoding
        try:
            plaintext_bytes = plaintext_str.encode('utf-8')
        except UnicodeEncodeError:
            return jsonify({
                'status': 'Error',
                'message': 'Invalid characters in message. Please use UTF-8 compatible text.'
            }), 400

        # --- Step 1: Kyber Key Generation ---
        start_time = time.time()
        pk, sk = kyber.keygen()
        timings['keygen_ms'] = round((time.time() - start_time) * 1000, 2)

        # --- Step 2: Kyber Encapsulation ---
        start_time = time.time()
        shared_secret_A, kyber_ciphertext = kyber.encaps(pk)
        timings['encaps_ms'] = round((time.time() - start_time) * 1000, 2)

        # --- Step 3: Kyber Decapsulation ---
        start_time = time.time()
        shared_secret_B = kyber.decaps(sk, kyber_ciphertext)
        timings['decaps_ms'] = round((time.time() - start_time) * 1000, 2)

        # --- Step 4: Apply Password Lock (Hybridization) ---
        # The actual key used for ChaCha20 is now dependent on BOTH Kyber and the Password
        encryption_key = derive_locked_key(shared_secret_A, password)
        decryption_key = derive_locked_key(shared_secret_B, password)

        # --- Step 5: ChaCha20-Poly1305 Encryption ---
        nonce = secrets.token_bytes(12)
        start_time = time.time()
        
        # Use Poly1305 for authentication
        message_ciphertext, auth_tag = chacha20_poly1305_encrypt(
            encryption_key, nonce, plaintext_bytes
        )
        timings['encrypt_ms'] = round((time.time() - start_time) * 1000, 2)

        # --- Step 6: ChaCha20-Poly1305 Decryption ---
        start_time = time.time()
        decrypted_plaintext_bytes = chacha20_poly1305_decrypt(
            decryption_key, nonce, message_ciphertext, auth_tag
        )
        timings['decrypt_ms'] = round((time.time() - start_time) * 1000, 2)
        
        # Calculate total time
        timings['total_ms'] = round(sum(timings.values()), 2)

        print(f"[INFO] Crypto completed - Total: {timings['total_ms']}ms")

        # --- Prepare the results for display ---
        results = {
            'status': 'Success',
            'kyber_pk': truncate_data(pk[1]),
            'kyber_sk': 'Private Key (kept secret)',
            'encapsulated_secret': shared_secret_A.hex(),
            'decapsulated_secret': shared_secret_B.hex(),
            'secrets_match': shared_secret_A == shared_secret_B,
            'nonce': nonce.hex(),
            'auth_tag': auth_tag.hex(),
            'original_plaintext': plaintext_str,
            'chacha_ciphertext': message_ciphertext.hex(),
            'decrypted_plaintext': decrypted_plaintext_bytes.decode('utf-8'),
            'performance': timings,
            'message_size_bytes': len(plaintext_bytes),
            'ciphertext_size_bytes': len(message_ciphertext)
        }
        
        return jsonify(results)

    except ValueError as e:
        return jsonify({
            'status': 'Error',
            'message': f'Validation/Auth Error: {str(e)} (Maybe incorrect secret key?)'
        }), 400
    
    except UnicodeDecodeError as e:
        return jsonify({
            'status': 'Error',
            'message': 'Decryption produced invalid UTF-8 text. Data may be corrupted.'
        }), 500
    
    except MemoryError:
        return jsonify({
            'status': 'Error',
            'message': 'Server out of memory. Please try with a smaller message.'
        }), 507
    
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"Unexpected Error:\n{error_trace}")
        
        return jsonify({
            'status': 'Error',
            'message': f'Unexpected server error: {str(e)}',
            'type': type(e).__name__
        }), 500

@app.route('/encrypt_file', methods=['POST'])
def encrypt_file():
    """
    Encrypt an uploaded file using Kyber + ChaCha20-Poly1305 + Optional Secret Key
    """
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({
                'status': 'Error',
                'message': 'No file provided'
            }), 400
        
        file = request.files['file']
        password = request.form.get('password', '') # Extract password from form data
        
        if file.filename == '':
            return jsonify({
                'status': 'Error',
                'message': 'No file selected'
            }), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                'status': 'Error',
                'message': f'File type not allowed. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}'
            }), 400
        
        # Read file data
        file_data = file.read()
        
        if len(file_data) == 0:
            return jsonify({
                'status': 'Error',
                'message': 'File is empty'
            }), 400
        
        print(f"[INFO] Encrypting file: {file.filename} ({len(file_data)} bytes)")
        
        # Generate Kyber keys
        pk, sk = kyber.keygen()
        shared_secret_A, kyber_ciphertext = kyber.encaps(pk)
        
        # Hybridize with password
        final_key = derive_locked_key(shared_secret_A, password)
        
        # Encrypt file with ChaCha20-Poly1305
        nonce = secrets.token_bytes(12)
        
        # Use filename as additional authenticated data
        aad = file.filename.encode('utf-8')
        ciphertext, tag = chacha20_poly1305_encrypt(
            final_key, nonce, file_data, aad
        )
        
        print(f"[INFO] File encrypted. Ciphertext: {len(ciphertext)} bytes")
        
        # Prepare response
        result = {
            'status': 'Success',
            'filename': file.filename,
            'original_size': len(file_data),
            'encrypted_size': len(ciphertext),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'shared_secret': shared_secret_A.hex()
        }
        
        return jsonify(result)
    
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"File Encryption Error:\n{error_trace}")
        
        return jsonify({
            'status': 'Error',
            'message': f'Encryption failed: {str(e)}'
        }), 500

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    """
    Decrypt a file using provided shared secret, metadata, and Secret Key
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['filename', 'nonce', 'tag', 'ciphertext', 'shared_secret']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'status': 'Error',
                    'message': f'Missing required field: {field}'
                }), 400
        
        print(f"[INFO] Decrypting file: {data['filename']}")
        
        # Decode data
        filename = data['filename']
        nonce = base64.b64decode(data['nonce'])
        tag = base64.b64decode(data['tag'])
        ciphertext = base64.b64decode(data['ciphertext'])
        shared_secret = bytes.fromhex(data['shared_secret'])
        password = data.get('password', '') # The password required to unlock the file
        
        # Re-derive the specific key using the password
        final_key = derive_locked_key(shared_secret, password)
        
        # Decrypt file
        aad = filename.encode('utf-8')
        
        plaintext = chacha20_poly1305_decrypt(
            final_key, nonce, ciphertext, tag, aad
        )
        
        print(f"[INFO] File decrypted. Size: {len(plaintext)} bytes")
        
        # Return decrypted data as base64
        result = {
            'status': 'Success',
            'filename': filename,
            'decrypted_size': len(plaintext),
            'data': base64.b64encode(plaintext).decode('utf-8')
        }
        
        return jsonify(result)
    
    except ValueError as e:
        print(f"[ERROR] Authentication failed: {e}")
        return jsonify({
            'status': 'Error',
            'message': 'Authentication failed! Incorrect secret key or corrupted file.'
        }), 401
    
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"File Decryption Error:\n{error_trace}")
        
        return jsonify({
            'status': 'Error',
            'message': f'Decryption failed: {str(e)}'
        }), 500

if __name__ == '__main__':
    print("=" * 70)
    print("POST-QUANTUM CRYPTOGRAPHY SERVER")
    print("=" * 70)
    print("Server starting on http://127.0.0.1:5000")
    print("Press Ctrl+C to stop")
    print("=" * 70)
    app.run(debug=True)