import struct

# This implementation is for educational purposes to meet the AAT project requirement
# of building a cryptographic algorithm from scratch. It is not intended for
# production use. Real-world applications should use vetted, audited cryptographic libraries.

def left_rotate(x, bits):
    """Performs a left bit rotation on a 32-bit integer."""
    return ((x << bits) | (x >> (32 - bits))) & 0xFFFFFFFF

def bytes_to_le_uint32_list(b):
    """Converts a byte string into a list of little-endian 32-bit integers."""
    return list(struct.unpack('<' + 'I' * (len(b) // 4), b))

def uint32_list_to_le_bytes(l):
    """Converts a list of 32-bit integers into a little-endian byte string."""
    return struct.pack('<' + 'I' * len(l), *l)

def quarter_round(a, b, c, d):
    """Performs the ChaCha20 quarter round operation on four 32-bit integers."""
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = left_rotate(d, 16)
    
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = left_rotate(b, 12)
    
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = left_rotate(d, 8)
    
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = left_rotate(b, 7)
    
    return a, b, c, d

def chacha20_block(key_list, nonce_list, counter):
    """
    Generates one 64-byte ChaCha20 block (the keystream).
    
    Args:
        key_list: A list of 8 32-bit integers (the 256-bit key).
        nonce_list: A list of 3 32-bit integers (the 96-bit nonce).
        counter: A 32-bit integer.
        
    Returns:
        A 64-byte keystream block.
    """
    # Initialize the 4x4 state matrix as a flat list of 16 elements.
    # See RFC 7539, Section 2.3.
    state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,  # Constants
        *key_list,                                       # Key
        counter,                                         # Counter
        *nonce_list                                      # Nonce
    ]
    
    initial_state = list(state)
    
    # Perform 10 double rounds (20 rounds total)
    for _ in range(10):
        # Column Round
        state[0], state[4], state[8], state[12] = quarter_round(state[0], state[4], state[8], state[12])
        state[1], state[5], state[9], state[13] = quarter_round(state[1], state[5], state[9], state[13])
        state[2], state[6], state[10], state[14] = quarter_round(state[2], state[6], state[10], state[14])
        state[3], state[7], state[11], state[15] = quarter_round(state[3], state[7], state[11], state[15])
        
        # Diagonal Round
        state[0], state[5], state[10], state[15] = quarter_round(state[0], state[5], state[10], state[15])
        state[1], state[6], state[11], state[12] = quarter_round(state[1], state[6], state[11], state[12])
        state[2], state[7], state[8], state[13] = quarter_round(state[2], state[7], state[8], state[13])
        state[3], state[4], state[9], state[14] = quarter_round(state[3], state[4], state[9], state[14])

    # Final addition: add the scrambled state to the initial state
    final_state = [(state[i] + initial_state[i]) & 0xFFFFFFFF for i in range(16)]
    
    # Convert the final state (list of integers) back to a byte string
    return uint32_list_to_le_bytes(final_state)


class ChaCha20:
    """A from-scratch implementation of the ChaCha20 stream cipher."""
    def __init__(self, key, nonce):
        """
        Initializes the cipher with a key and a nonce.
        
        Args:
            key: 32 bytes (256 bits)
            nonce: 12 bytes (96 bits)
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes long")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes long")
            
        self.key = key
        self.nonce = nonce
        self._key_list = bytes_to_le_uint32_list(key)
        self._nonce_list = bytes_to_le_uint32_list(nonce)

    def encrypt(self, plaintext):
        """
        Encrypts the given plaintext.
        
        Args:
            plaintext: The data to encrypt, as bytes.
            
        Returns:
            The ciphertext, as bytes.
        """
        ciphertext = b''
        block_counter = 1 # ChaCha20 counter usually starts at 1
        
        for i in range(0, len(plaintext), 64):
            # Generate the next 64-byte keystream block
            keystream = chacha20_block(self._key_list, self._nonce_list, block_counter)
            
            # Get the current chunk of plaintext
            plaintext_chunk = plaintext[i : i + 64]
            
            # XOR the plaintext chunk with the keystream
            # This is the core of a stream cipher
            encrypted_chunk = bytes([p ^ k for p, k in zip(plaintext_chunk, keystream)])
            
            ciphertext += encrypted_chunk
            block_counter += 1
            
        # CORRECTED: The return statement must be outside the for loop.
        return ciphertext

    def decrypt(self, ciphertext):
        """
        Decrypts the given ciphertext.
        In a stream cipher, decryption is the same operation as encryption.
        """
        return self.encrypt(ciphertext)


# --- SELF-TESTING SECTION ---
if __name__ == "__main__":
    print("--- Running ChaCha20 Self-Test ---")
    
    # This test vector is from RFC 7539, Section 2.4.2.
    # It allows us to verify if our implementation is correct.
    
    # 1. SETUP THE TEST DATA
    # Key (32 bytes)
    key_hex = (
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    )
    key = bytes.fromhex(key_hex)
    
    # Nonce (12 bytes)
    nonce_hex = "000000000001020304050607"
    nonce = bytes.fromhex(nonce_hex)
    
    # Plaintext (114 bytes)
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
        b"for the future, sunscreen would be it."
    )

    # Expected Ciphertext (from the RFC) - CORRECTED
    expected_ciphertext_hex = (
        "6e2e359a2568f98041ba0728dd0d6981e97e7a78c20a27afccfd9fae0bf91b65"
        "c5523863886ae6593ca652c2c4b14c58c5879029bfd64f51638763895096a517"
        "ad081cfa9f59cce310d377cee42b413520e08ab5ca24260e278675817645b497"
        "a9234910491c7e7e6b821d9d6654"
    )
    expected_ciphertext = bytes.fromhex(expected_ciphertext_hex)

    # 2. PERFORM ENCRYPTION
    print("Encrypting plaintext...")
    cipher = ChaCha20(key, nonce)
    actual_ciphertext = cipher.encrypt(plaintext)

    # 3. VERIFY THE RESULT
    print(f"Plaintext length:  {len(plaintext)}")
    print(f"Ciphertext length: {len(actual_ciphertext)}")
    
    if actual_ciphertext == expected_ciphertext:
        print("\nSUCCESS: Generated ciphertext matches the RFC 7539 test vector!")
    else:
        print("\nFAILURE: Generated ciphertext does NOT match the test vector.")
        print(f"Expected: {expected_ciphertext.hex()}")
        print(f"Actual:   {actual_ciphertext.hex()}")

    # 4. TEST DECRYPTION
    print("\nDecrypting ciphertext...")
    decrypted_plaintext = cipher.decrypt(actual_ciphertext)

    if decrypted_plaintext == plaintext:
        print("SUCCESS: Decryption returned the original plaintext!")
    else:
        print("FAILURE: Decryption failed.")