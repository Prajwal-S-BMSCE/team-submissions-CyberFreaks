# This implementation is for educational purposes to meet the AAT project requirement
# of building a cryptographic algorithm from scratch. It is not intended for
# production use. This file implements SHAKE128 and SHAKE256, which are
# required by the CRYSTALS-Kyber algorithm.

# --- Keccak constants ---
KECCAK_ROUNDS = 24
KECCAK_ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
]

def _left_rotate64(x, n):
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

def _keccak_f1600(state):
    """The core permutation function for Keccak/SHA-3."""
    for round_index in range(KECCAK_ROUNDS):
        # Theta step
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _left_rotate64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]

        # Rho and Pi steps
        temp_x, temp_y = 1, 0
        current = state[temp_x][temp_y]
        for _ in range(24):
            shift = ((_ + 1) * (_ + 2) // 2) % 64
            next_x, next_y = temp_y, (2 * temp_x + 3 * temp_y) % 5
            next_val = state[next_x][next_y]
            state[next_x][next_y] = _left_rotate64(current, shift)
            current = next_val
            temp_x, temp_y = next_x, next_y
            
        # Chi step
        for y in range(5):
            t = [state[x][y] for x in range(5)]
            for x in range(5):
                state[x][y] = t[x] ^ ((~t[(x + 1) % 5]) & t[(x + 2) % 5])

        # Iota step
        state[0][0] ^= KECCAK_ROUND_CONSTANTS[round_index]

    return state

class SHAKE:
    """
    A from-scratch implementation of the SHAKE extendable-output functions (XOFs).
    """
    def __init__(self, bitrate):
        """
        Initializes the SHAKE instance.
        Args:
            bitrate: The bitrate in bits. 1344 for SHAKE128, 1088 for SHAKE256.
        """
        if bitrate not in [1344, 1088]:
            raise ValueError("Invalid SHAKE bitrate")
        
        self.block_size = bitrate // 8
        
        # State is a 5x5 matrix of 64-bit integers
        self._state = [[0] * 5 for _ in range(5)]
        self._buffer = b''

    def _absorb_block(self, block):
        for y in range(5):
            for x in range(5):
                # Extract 8 bytes (64 bits) for each state integer
                offset = (5 * y + x) * 8
                chunk = block[offset : offset + 8]
                if len(chunk) < 8: # Should not happen with proper padding
                    chunk += b'\x00' * (8 - len(chunk))
                
                self._state[x][y] ^= int.from_bytes(chunk, 'little')
        _keccak_f1600(self._state)

    def update(self, data):
        """Absorb input data into the sponge."""
        self._buffer += data
        while len(self._buffer) >= self.block_size:
            block = self._buffer[:self.block_size]
            self._buffer = self._buffer[self.block_size:]
            self._absorb_block(block)

    def _finalize(self):
        # Finalize the absorption phase with padding.
        # For SHAKE, the padding is 0b1111, which is 0x1F.
        self._buffer += b'\x1f'
        while len(self._buffer) < self.block_size:
            self._buffer += b'\x00'
        
        # Absorb the final padded block
        self._absorb_block(self._buffer)
        self._buffer = b''

    def read(self, length):
        """Squeeze out `length` bytes of output."""
        self._finalize()
        
        output = b''
        while len(output) < length:
            # Squeeze a block
            for y in range(5):
                for x in range(5):
                    output += self._state[x][y].to_bytes(8, 'little')
            
            # If more output is needed, run the permutation again
            if len(output) < length:
                _keccak_f1600(self._state)
                
        return output[:length]

# Convenience functions for direct use
def shake128(data, length):
    s = SHAKE(1344)
    s.update(data)
    return s.read(length)

def shake256(data, length):
    s = SHAKE(1088)
    s.update(data)
    return s.read(length)

# --- SELF-TESTING SECTION ---
if __name__ == "__main__":
    print("--- Running SHAKE Self-Test ---")
    
    # Test vector from NIST FIPS 202
    input_data = b""
    expected_shake128_hex = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
    
    output_shake128 = shake128(input_data, 32)
    
    print("SHAKE128 Test:")
    print(f"Input:    (empty string)")
    print(f"Output:   {output_shake128.hex()}")
    print(f"Expected: {expected_shake128_hex}")
    
    if output_shake128.hex() == expected_shake128_hex:
        print("SUCCESS: SHAKE128 output matches the test vector!\n")
    else:
        print("FAILURE: SHAKE128 output does not match.\n")
        
    expected_shake256_hex = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
    
    output_shake256 = shake256(input_data, 64)
    
    print("SHAKE256 Test:")
    print(f"Input:    (empty string)")
    print(f"Output:   {output_shake256.hex()}")
    print(f"Expected: {expected_shake256_hex}")
    
    if output_shake256.hex() == expected_shake256_hex:
        print("SUCCESS: SHAKE256 output matches the test vector!")
    else:
        print("FAILURE: SHAKE256 output does not match.")
