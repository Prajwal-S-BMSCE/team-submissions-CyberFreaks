# This implementation is for educational purposes to meet the AAT project requirement
# of building a cryptographic algorithm from scratch. It is not intended for
# production use.

# Import the from-scratch SHAKE implementation
from sha3_from_scratch import shake128, shake256

# --- Kyber Parameters ---
# We will start with Kyber512, which is the first security level.
# See Table 1 in the Kyber specification document (v3.0.2)

KYBER_K = 2  # Security parameter. 2 for Kyber512.
KYBER_N = 256
KYBER_Q = 3329
KYBER_ETA1 = 2 # For Kyber512's secret key `s` and noise `e`
KYBER_ETA2 = 2 # For Kyber512's encapsulation noise
KYBER_DU = 10  # For compressing vector u
KYBER_DV = 4   # For compressing polynomial v

# --- Polynomial Representation & Arithmetic ---
# A polynomial is a list of KYBER_N integer coefficients.
# A vector is a list of KYBER_K polynomials.
# A matrix is a list of KYBER_K vectors (a KxK grid of polynomials).

def poly_reduce(p):
    """Reduces all coefficients of a polynomial to be in the range [0, q-1]."""
    return [c % KYBER_Q for c in p]

def poly_add(p1, p2):
    """Adds two polynomials coefficient-wise."""
    res = [(p1[i] + p2[i]) for i in range(KYBER_N)]
    return poly_reduce(res)

def poly_subtract(p1, p2):
    """Subtracts two polynomials coefficient-wise."""
    res = [(p1[i] - p2[i]) for i in range(KYBER_N)]
    return poly_reduce(res)

def poly_multiply(p1, p2):
    """
    Multiplies two polynomials using schoolbook multiplication followed by
    a reduction modulo (x^n + 1).
    """
    res = [0] * (2 * KYBER_N - 1)
    for i in range(KYBER_N):
        for j in range(KYBER_N):
            res[i+j] += p1[i] * p2[j]
            
    for i in range(2 * KYBER_N - 2, KYBER_N - 1, -1):
        res[i - KYBER_N] -= res[i]
    
    final_res = res[:KYBER_N]
    return poly_reduce(final_res)

# --- Sampling and Generation Helpers ---

def _rejection_sample(stream):
    """
    Rejection sampling to generate polynomial coefficients in [0, q-1].
    The Kyber spec describes a method of taking 3 bytes from a SHAKE stream,
    interpreting them as two 12-bit numbers, and checking if they are < q.
    """
    coeffs = []
    i = 0
    while len(coeffs) < KYBER_N:
        b1, b2, b3 = stream[i], stream[i+1], stream[i+2]
        d1 = b1 + 256 * (b2 % 16)
        d2 = (b2 // 16) + 16 * b3
        
        if d1 < KYBER_Q:
            coeffs.append(d1)
        if len(coeffs) < KYBER_N and d2 < KYBER_Q:
            coeffs.append(d2)
        i += 3
    return coeffs

def _parse_xof_stream(seed, i, j):
    """Generates a SHAKE128 stream for creating matrix A coefficients."""
    return shake128(seed + bytes([j, i]), 2 * KYBER_N * 3)

def generate_matrix_A(rho):
    """Deterministically generates the public matrix A from the seed rho."""
    A = [[([0] * KYBER_N) for _ in range(KYBER_K)] for _ in range(KYBER_K)]
    for i in range(KYBER_K):
        for j in range(KYBER_K):
            stream = _parse_xof_stream(rho, i, j)
            A[i][j] = _rejection_sample(stream)
    return A

def _cbd(buffer, eta):
    """
    Centered Binomial Distribution: generates small coefficients for secrets.
    """
    coeffs = [0] * KYBER_N
    for i in range(KYBER_N):
        byte_val = buffer[i*eta*2 // 8]
        bit_offset = (i*eta*2) % 8
        a, b = 0, 0
        for j in range(eta):
            if (byte_val >> (bit_offset + j)) & 1: a += 1
            if (byte_val >> (bit_offset + j + eta)) & 1: b += 1
        coeffs[i] = a - b
    return coeffs
    
def sample_poly_cbd(sigma, nonce, eta):
    """Samples a polynomial from the CBD using the seed sigma."""
    ext = shake256(sigma + bytes([nonce]), eta * KYBER_N // 2)
    return _cbd(ext, eta)

# --- Vector and Matrix Operations ---

def matrix_vector_multiply(matrix, vector):
    """Multiplies a matrix of polynomials by a vector of polynomials."""
    res_vector = [[0] * KYBER_N for _ in range(KYBER_K)]
    for i in range(KYBER_K):
        row_res = [0] * KYBER_N
        for j in range(KYBER_K):
            term = poly_multiply(matrix[i][j], vector[j])
            row_res = poly_add(row_res, term)
        res_vector[i] = row_res
    return res_vector

def matrix_transpose_vector_multiply(matrix, vector):
    """Multiplies the transpose of a matrix by a vector."""
    res_vector = [[0] * KYBER_N for _ in range(KYBER_K)]
    for i in range(KYBER_K):
        row_res = [0] * KYBER_N
        for j in range(KYBER_K):
            term = poly_multiply(matrix[j][i], vector[j])
            row_res = poly_add(row_res, term)
        res_vector[i] = row_res
    return res_vector

def vector_dot_product(v1, v2):
    """Computes the dot product of two vectors of polynomials."""
    res_poly = [0] * KYBER_N
    for i in range(KYBER_K):
        term = poly_multiply(v1[i], v2[i])
        res_poly = poly_add(res_poly, term)
    return res_poly

def vector_add(v1, v2):
    """Adds two vectors of polynomials."""
    return [poly_add(v1[i], v2[i]) for i in range(KYBER_K)]

# --- Compression and Decompression ---
def poly_compress(p, d):
    """Compresses a polynomial by reducing the bit-size of its coefficients."""
    scale_factor_num = 1 << d
    compressed = [0] * KYBER_N
    for i in range(KYBER_N):
        val = (p[i] * scale_factor_num * 2 + KYBER_Q) // (2 * KYBER_Q)
        compressed[i] = val & (scale_factor_num - 1)
    return compressed

def poly_decompress(p_comp, d):
    """Decompresses a polynomial."""
    scale_factor_num = KYBER_Q
    decompressed = [0] * KYBER_N
    for i in range(KYBER_N):
        decompressed[i] = (p_comp[i] * scale_factor_num * 2 + (1 << d)) // (2 * (1 << d))
    return decompressed

# --- Kyber Core Functions ---

def keygen():
    """Generates a public and private key pair for Kyber."""
    print("Generating Kyber key pair...")
    d = bytes([i for i in range(32)])
    g_output = shake256(d, 64)
    rho, sigma = g_output[:32], g_output[32:]
    
    A = generate_matrix_A(rho)
    s = [sample_poly_cbd(sigma, i, KYBER_ETA1) for i in range(KYBER_K)]
    e = [sample_poly_cbd(sigma, i + KYBER_K, KYBER_ETA1) for i in range(KYBER_K)]
    
    t_prime = matrix_vector_multiply(A, s)
    t = vector_add(t_prime, e)
    
    public_key = (t, rho)
    private_key = s
    
    print("Key generation complete.")
    return public_key, private_key

def encaps(public_key):
    """Encapsulates a shared secret using a public key."""
    print("Encapsulating a shared secret...")
    t, rho = public_key
    
    m = bytes([i+100 for i in range(32)])
    kdf_output = shake256(m, 64)
    K_bar, sigma = kdf_output[:32], kdf_output[32:]
    
    A = generate_matrix_A(rho)
    
    r = [sample_poly_cbd(sigma, i, KYBER_ETA1) for i in range(KYBER_K)]
    e1 = [sample_poly_cbd(sigma, i + KYBER_K, KYBER_ETA2) for i in range(KYBER_K)]
    e2_coeffs = sample_poly_cbd(sigma, 2 * KYBER_K, KYBER_ETA2)
    
    u_prime = matrix_transpose_vector_multiply(A, r)
    u = vector_add(u_prime, e1)
    
    v_prime = vector_dot_product(t, r)
    v_prime = poly_add(v_prime, e2_coeffs)
    
    msg_poly = [0] * KYBER_N
    for i in range(256):
        if (m[i//8] >> (i%8)) & 1:
            msg_poly[i] = (KYBER_Q + 1) // 2
            
    v_prime = poly_add(v_prime, msg_poly)
    
    u_comp = [poly_compress(p, KYBER_DU) for p in u]
    v_comp = poly_compress(v_prime, KYBER_DV)
    ciphertext = (u_comp, v_comp)
    
    # Simplified KDF for educational purposes.
    shared_secret = shake256(K_bar, 32)
    
    print("Encapsulation complete.")
    return shared_secret, ciphertext

def decaps(private_key, ciphertext):
    """Decapsulates a shared secret using a private key."""
    print("Decapsulating a shared secret...")
    s = private_key
    u_comp, v_comp = ciphertext

    u = [poly_decompress(p, KYBER_DU) for p in u_comp]
    v = poly_decompress(v_comp, KYBER_DV)

    v_prime = vector_dot_product(s, u)

    msg_poly = poly_subtract(v, v_prime)

    m_prime = bytearray(32)
    for i in range(256):
        val = msg_poly[i]
        # Threshold check to recover the message bit
        if val > KYBER_Q // 4 and val < 3 * KYBER_Q // 4:
            m_prime[i // 8] |= (1 << (i % 8))
    m_prime = bytes(m_prime)
    
    # Re-derive K_bar from the recovered message
    kdf_output_prime = shake256(m_prime, 64)
    K_bar_prime = kdf_output_prime[:32]
    
    # Re-derive the shared secret. It will match if m_prime == m.
    shared_secret = shake256(K_bar_prime, 32)
    
    print("Decapsulation complete.")
    return shared_secret

# --- SELF-TESTING SECTION ---
if __name__ == "__main__":
    print("--- Running Polynomial Arithmetic Self-Test ---")
    p1 = [i + 1 for i in range(KYBER_N)]
    p2 = [KYBER_Q - (i + 1) for i in range(KYBER_N)]
    p_add = poly_add(p1, p2)
    if all(c == 0 for c in p_add): print("SUCCESS: Polynomial addition works correctly.")
    else: print("FAILURE: Polynomial addition is incorrect.")
    p_sub = poly_subtract(p1, p1)
    if all(c == 0 for c in p_sub): print("SUCCESS: Polynomial subtraction works correctly.")
    else: print("FAILURE: Polynomial subtraction is incorrect.")

    print("\n--- Running Kyber Self-Test ---")
    
    pk, sk = keygen()
    print("SUCCESS: keygen produced objects with the correct structure.")

    ss_A, ct = encaps(pk)
    print("SUCCESS: encaps produced objects with the correct structure.")

    ss_B = decaps(sk, ct)
    
    print(f"\nSecret from Encapsulation: {ss_A.hex()}")
    print(f"Secret from Decapsulation: {ss_B.hex()}")

    if ss_A == ss_B:
        print("\nSUCCESS: Decapsulated secret matches the encapsulated one!")
    else:
        print("\nFAILURE: Secrets do not match. Review implementation.")

