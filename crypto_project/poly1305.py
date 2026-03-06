"""
Poly1305 Message Authentication Code (MAC)
RFC 7539 compliant implementation for ChaCha20-Poly1305 AEAD
Educational implementation - built from scratch
"""

def clamp(r):
    """Clamp the r value according to RFC 7539 Section 2.5"""
    return r & 0x0ffffffc0ffffffc0ffffffc0fffffff

def poly1305_mac(msg, key):
    """
    Compute Poly1305 MAC for a message.
    
    Args:
        msg: Message bytes to authenticate
        key: 32-byte key (first 16 bytes for r, last 16 bytes for s)
    
    Returns:
        16-byte MAC tag
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    
    # Split key into r and s
    r = int.from_bytes(key[0:16], 'little')
    s = int.from_bytes(key[16:32], 'little')
    
    # Clamp r
    r = clamp(r)
    
    # Prime number for modular arithmetic
    p = (1 << 130) - 5
    
    # Initialize accumulator
    accumulator = 0
    
    # Process message in 16-byte chunks
    for i in range(0, len(msg), 16):
        # Get chunk (pad if needed)
        chunk = msg[i:i+16]
        
        # Convert chunk to integer (little-endian) and add 0x01 byte
        if len(chunk) == 16:
            n = int.from_bytes(chunk + b'\x01', 'little')
        else:
            # Last chunk - pad with 0x01
            n = int.from_bytes(chunk + b'\x01', 'little')
        
        # Accumulate: (accumulator + n) * r mod p
        accumulator = ((accumulator + n) * r) % p
    
    # Add s (no modulo)
    tag = (accumulator + s) & 0xffffffffffffffffffffffffffffffff
    
    # Convert to 16-byte little-endian
    return tag.to_bytes(16, 'little')


def poly1305_key_gen(key, nonce):
    """
    Generate Poly1305 key using ChaCha20.
    
    Args:
        key: 32-byte ChaCha20 key
        nonce: 12-byte nonce
    
    Returns:
        32-byte Poly1305 key
    """
    from chacha20 import ChaCha20
    
    # Use ChaCha20 with counter=0 to generate Poly1305 key
    cipher = ChaCha20(key, nonce)
    # Encrypt 32 zero bytes to get the key
    poly_key = cipher.encrypt(b'\x00' * 32)
    
    return poly_key


def pad16(data):
    """Pad data to 16-byte boundary"""
    remainder = len(data) % 16
    if remainder == 0:
        return b''
    return b'\x00' * (16 - remainder)


def chacha20_poly1305_encrypt(key, nonce, plaintext, aad=b''):
    """
    ChaCha20-Poly1305 AEAD encryption.
    
    Args:
        key: 32-byte encryption key
        nonce: 12-byte nonce
        plaintext: Data to encrypt
        aad: Additional Authenticated Data (optional)
    
    Returns:
        (ciphertext, tag) tuple
    """
    from chacha20 import ChaCha20
    
    # Generate Poly1305 key
    poly_key = poly1305_key_gen(key, nonce)
    
    # Encrypt plaintext with ChaCha20 (counter starts at 1)
    cipher = ChaCha20(key, nonce)
    # Skip first block (counter 0 used for poly key)
    cipher.encrypt(b'\x00' * 64)  # Advance counter
    ciphertext = cipher.encrypt(plaintext)
    
    # Construct message for MAC
    mac_data = aad + pad16(aad)
    mac_data += ciphertext + pad16(ciphertext)
    mac_data += len(aad).to_bytes(8, 'little')
    mac_data += len(ciphertext).to_bytes(8, 'little')
    
    # Compute MAC tag
    tag = poly1305_mac(mac_data, poly_key)
    
    return ciphertext, tag


def chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad=b''):
    """
    ChaCha20-Poly1305 AEAD decryption.
    
    Args:
        key: 32-byte encryption key
        nonce: 12-byte nonce
        ciphertext: Encrypted data
        tag: 16-byte authentication tag
        aad: Additional Authenticated Data (optional)
    
    Returns:
        plaintext if authentication succeeds
    
    Raises:
        ValueError: If authentication fails
    """
    from chacha20 import ChaCha20
    
    # Generate Poly1305 key
    poly_key = poly1305_key_gen(key, nonce)
    
    # Construct message for MAC verification
    mac_data = aad + pad16(aad)
    mac_data += ciphertext + pad16(ciphertext)
    mac_data += len(aad).to_bytes(8, 'little')
    mac_data += len(ciphertext).to_bytes(8, 'little')
    
    # Compute expected MAC tag
    expected_tag = poly1305_mac(mac_data, poly_key)
    
    # Constant-time comparison
    if not constant_time_compare(tag, expected_tag):
        raise ValueError("Authentication failed! Message has been tampered with.")
    
    # Decrypt plaintext with ChaCha20
    cipher = ChaCha20(key, nonce)
    # Skip first block (counter 0 used for poly key)
    cipher.encrypt(b'\x00' * 64)  # Advance counter
    plaintext = cipher.decrypt(ciphertext)
    
    return plaintext


def constant_time_compare(a, b):
    """Constant-time comparison to prevent timing attacks"""
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0