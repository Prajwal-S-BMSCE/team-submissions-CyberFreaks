"""
Test Suite for Post-Quantum Cryptography Project
Run with: python test_crypto.py
"""

import unittest
import sys
import kyber
from chacha20 import ChaCha20
from sha3_from_scratch import shake128, shake256

class TestKyber(unittest.TestCase):
    """Test CRYSTALS-Kyber implementation"""
    
    def test_keygen_returns_valid_keys(self):
        """Test that key generation produces valid key pairs"""
        pk, sk = kyber.keygen()
        
        # Public key should be a tuple (t, rho)
        self.assertIsInstance(pk, tuple)
        self.assertEqual(len(pk), 2)
        
        # Private key should be a list of polynomials
        self.assertIsInstance(sk, list)
        self.assertEqual(len(sk), kyber.KYBER_K)
    
    def test_encaps_decaps_produces_same_secret(self):
        """Test that encapsulation and decapsulation produce matching secrets"""
        pk, sk = kyber.keygen()
        
        # Encapsulate
        ss_A, ciphertext = kyber.encaps(pk)
        
        # Decapsulate
        ss_B = kyber.decaps(sk, ciphertext)
        
        # Secrets should match
        self.assertEqual(ss_A, ss_B, "Shared secrets don't match!")
        self.assertEqual(len(ss_A), 32, "Shared secret should be 32 bytes")
    
    def test_multiple_encaps_produce_different_secrets(self):
        """Test that multiple encapsulations produce different secrets"""
        pk, sk = kyber.keygen()
        
        ss_1, ct_1 = kyber.encaps(pk)
        ss_2, ct_2 = kyber.encaps(pk)
        
        # Different encapsulations should produce different secrets
        self.assertNotEqual(ss_1, ss_2, "Encapsulation should be randomized!")
    
    def test_polynomial_operations(self):
        """Test basic polynomial arithmetic"""
        p1 = [1, 2, 3] + [0] * (kyber.KYBER_N - 3)
        p2 = [4, 5, 6] + [0] * (kyber.KYBER_N - 3)
        
        # Test addition
        p_add = kyber.poly_add(p1, p2)
        self.assertEqual(p_add[0], 5)
        self.assertEqual(p_add[1], 7)
        self.assertEqual(p_add[2], 9)
        
        # Test subtraction
        p_sub = kyber.poly_subtract(p1, p1)
        self.assertTrue(all(c == 0 for c in p_sub))


class TestChaCha20(unittest.TestCase):
    """Test ChaCha20 implementation"""
    
    def test_rfc7539_test_vector(self):
        """Test against official RFC 7539 test vector"""
        key_hex = (
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        )
        key = bytes.fromhex(key_hex)
        
        nonce_hex = "000000000001020304050607"
        nonce = bytes.fromhex(nonce_hex)
        
        plaintext = (
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
            b"for the future, sunscreen would be it."
        )
        
        expected_ciphertext_hex = (
            "6e2e359a2568f98041ba0728dd0d6981e97e7a78c20a27afccfd9fae0bf91b65"
            "c5523863886ae6593ca652c2c4b14c58c5879029bfd64f51638763895096a517"
            "ad081cfa9f59cce310d377cee42b413520e08ab5ca24260e278675817645b497"
            "a9234910491c7e7e6b821d9d6654"
        )
        expected_ciphertext = bytes.fromhex(expected_ciphertext_hex)
        
        cipher = ChaCha20(key, nonce)
        actual_ciphertext = cipher.encrypt(plaintext)
        
        self.assertEqual(actual_ciphertext, expected_ciphertext,
                        "ChaCha20 output doesn't match RFC 7539 test vector!")
    
    def test_encryption_decryption_symmetry(self):
        """Test that encryption and decryption are symmetric"""
        key = b'A' * 32
        nonce = b'B' * 12
        plaintext = b"Hello, World! This is a test message."
        
        cipher = ChaCha20(key, nonce)
        ciphertext = cipher.encrypt(plaintext)
        
        decipher = ChaCha20(key, nonce)
        decrypted = decipher.decrypt(ciphertext)
        
        self.assertEqual(plaintext, decrypted,
                        "Decrypted text doesn't match original!")
    
    def test_different_keys_produce_different_ciphertext(self):
        """Test that different keys produce different ciphertext"""
        key1 = b'A' * 32
        key2 = b'B' * 32
        nonce = b'C' * 12
        plaintext = b"Secret message"
        
        cipher1 = ChaCha20(key1, nonce)
        cipher2 = ChaCha20(key2, nonce)
        
        ciphertext1 = cipher1.encrypt(plaintext)
        ciphertext2 = cipher2.encrypt(plaintext)
        
        self.assertNotEqual(ciphertext1, ciphertext2,
                           "Different keys should produce different ciphertext!")
    
    def test_invalid_key_length(self):
        """Test that invalid key length raises error"""
        with self.assertRaises(ValueError):
            ChaCha20(key=b'short', nonce=b'X' * 12)
    
    def test_invalid_nonce_length(self):
        """Test that invalid nonce length raises error"""
        with self.assertRaises(ValueError):
            ChaCha20(key=b'A' * 32, nonce=b'short')


class TestSHA3(unittest.TestCase):
    """Test SHAKE implementation"""
    
    def test_shake128_empty_input(self):
        """Test SHAKE128 with empty input against known answer"""
        expected = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        output = shake128(b"", 32)
        self.assertEqual(output.hex(), expected,
                        "SHAKE128 doesn't match NIST test vector!")
    
    def test_shake256_empty_input(self):
        """Test SHAKE256 with empty input against known answer"""
        expected = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        output = shake256(b"", 64)
        self.assertEqual(output.hex(), expected,
                        "SHAKE256 doesn't match NIST test vector!")
    
    def test_shake_different_lengths(self):
        """Test that SHAKE can produce variable-length outputs"""
        input_data = b"test"
        
        output_16 = shake128(input_data, 16)
        output_32 = shake128(input_data, 32)
        output_64 = shake128(input_data, 64)
        
        self.assertEqual(len(output_16), 16)
        self.assertEqual(len(output_32), 32)
        self.assertEqual(len(output_64), 64)


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete system"""
    
    def test_full_hybrid_encryption_workflow(self):
        """Test the complete Kyber + ChaCha20 workflow"""
        import secrets
        
        # Original message
        original_message = b"This is a secret message for hybrid encryption test!"
        
        # Step 1: Kyber key generation
        pk, sk = kyber.keygen()
        
        # Step 2: Encapsulation
        shared_secret_A, kyber_ciphertext = kyber.encaps(pk)
        
        # Step 3: Decapsulation
        shared_secret_B = kyber.decaps(sk, kyber_ciphertext)
        
        # Verify secrets match
        self.assertEqual(shared_secret_A, shared_secret_B)
        
        # Step 4: Encrypt with ChaCha20
        nonce = secrets.token_bytes(12)
        cipher = ChaCha20(key=shared_secret_A, nonce=nonce)
        ciphertext = cipher.encrypt(original_message)
        
        # Step 5: Decrypt with ChaCha20
        decipher = ChaCha20(key=shared_secret_B, nonce=nonce)
        decrypted_message = decipher.decrypt(ciphertext)
        
        # Verify message integrity
        self.assertEqual(original_message, decrypted_message,
                        "Full workflow failed - message doesn't match!")

class TestPoly1305(unittest.TestCase):
    """Test Poly1305 MAC implementation"""
    
    def test_rfc7539_test_vector(self):
        """Test Poly1305 against RFC 7539 test vector"""
        from poly1305 import poly1305_mac
        
        msg = b"Cryptographic Forum Research Group"
        key = bytes.fromhex(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b"
        )
        
        expected_tag = bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")
        computed_tag = poly1305_mac(msg, key)
        
        self.assertEqual(computed_tag, expected_tag,
                        "Poly1305 doesn't match RFC 7539 test vector!")
    
    def test_chacha20_poly1305_aead(self):
        """Test ChaCha20-Poly1305 AEAD"""
        from poly1305 import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt
        import secrets
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Secret message for AEAD test"
        aad = b"additional data"
        
        # Encrypt
        ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext, aad)
        
        # Decrypt
        decrypted = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad)
        
        self.assertEqual(plaintext, decrypted,
                        "AEAD decryption failed!")
    
    def test_tampering_detection(self):
        """Test that tampering is detected"""
        from poly1305 import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt
        import secrets
        
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Secret message"
        
        ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 1
        
        # Should raise ValueError
        with self.assertRaises(ValueError):
            chacha20_poly1305_decrypt(key, nonce, bytes(tampered), tag)


class TestNTT(unittest.TestCase):
    """Test NTT implementation"""
    
    def test_ntt_round_trip(self):
        """Test that NTT forward/inverse is correct"""
        from ntt import ntt_forward, ntt_inverse, KYBER_N, KYBER_Q
        
        # Create test polynomial
        original = [i % KYBER_Q for i in range(KYBER_N)]
        
        # Transform to NTT domain and back
        ntt_domain = ntt_forward(original)
        recovered = ntt_inverse(ntt_domain)
        
        # Check if we get back the original
        for i in range(KYBER_N):
            self.assertEqual(original[i] % KYBER_Q, recovered[i] % KYBER_Q,
                           f"NTT round-trip failed at index {i}")
    
    def test_ntt_multiplication_correctness(self):
        """Test that NTT multiplication produces correct results"""
        from ntt import poly_multiply_ntt, KYBER_N
        import kyber
        
        # Small test polynomials
        poly1 = [1, 2, 3, 4] + [0] * (KYBER_N - 4)
        poly2 = [5, 6, 7, 8] + [0] * (KYBER_N - 4)
        
        # Multiply using NTT (fast)
        result_ntt = poly_multiply_ntt(poly1, poly2)
        
        # Multiply using schoolbook (slow but correct)
        result_slow = kyber.poly_multiply(poly1, poly2)
        
        # Results should match (modulo q)
        from ntt import KYBER_Q
        for i in range(KYBER_N):
            self.assertEqual(result_ntt[i] % KYBER_Q, result_slow[i] % KYBER_Q,
                           f"NTT multiplication doesn't match at index {i}")
    
    def test_ntt_performance_improvement(self):
        """Test that NTT is faster than schoolbook"""
        from ntt import poly_multiply_ntt, KYBER_N
        import kyber
        import time
        
        # Random polynomials
        import random
        poly1 = [random.randint(0, 3328) for _ in range(KYBER_N)]
        poly2 = [random.randint(0, 3328) for _ in range(KYBER_N)]
        
        # Time NTT multiplication
        start = time.time()
        for _ in range(10):
            poly_multiply_ntt(poly1, poly2)
        ntt_time = time.time() - start
        
        # Time schoolbook multiplication
        start = time.time()
        for _ in range(10):
            kyber.poly_multiply(poly1, poly2)
        slow_time = time.time() - start
        
        # NTT should be faster
        self.assertLess(ntt_time, slow_time,
                       "NTT should be faster than schoolbook multiplication")
        
        print(f"\n  NTT speedup: {slow_time/ntt_time:.2f}x faster")


class TestPerformance(unittest.TestCase):
    """Performance benchmarking tests"""
    
    def test_full_workflow_performance(self):
        """Benchmark the complete cryptographic workflow"""
        import time
        import kyber
        from chacha20 import ChaCha20
        import secrets
        
        message = b"Performance test message" * 100  # ~2.5KB
        
        # Measure key generation
        start = time.time()
        pk, sk = kyber.keygen()
        keygen_time = time.time() - start
        
        # Measure encapsulation
        start = time.time()
        ss_A, ct = kyber.encaps(pk)
        encaps_time = time.time() - start
        
        # Measure decapsulation
        start = time.time()
        ss_B = kyber.decaps(sk, ct)
        decaps_time = time.time() - start
        
        # Measure encryption
        nonce = secrets.token_bytes(12)
        start = time.time()
        cipher = ChaCha20(ss_A, nonce)
        ciphertext = cipher.encrypt(message)
        encrypt_time = time.time() - start
        
        # Measure decryption
        start = time.time()
        decipher = ChaCha20(ss_B, nonce)
        plaintext = decipher.decrypt(ciphertext)
        decrypt_time = time.time() - start
        
        total_time = keygen_time + encaps_time + decaps_time + encrypt_time + decrypt_time
        
        print(f"\n  Performance Benchmark Results:")
        print(f"  - Key Generation: {keygen_time*1000:.2f} ms")
        print(f"  - Encapsulation:  {encaps_time*1000:.2f} ms")
        print(f"  - Decapsulation:  {decaps_time*1000:.2f} ms")
        print(f"  - Encryption:     {encrypt_time*1000:.2f} ms")
        print(f"  - Decryption:     {decrypt_time*1000:.2f} ms")
        print(f"  - Total Time:     {total_time*1000:.2f} ms")
        
        # Verify correctness
        self.assertEqual(message, plaintext)
        self.assertEqual(ss_A, ss_B)

def run_tests():
    """Run all tests and display results"""
    print("=" * 70)
    print("POST-QUANTUM CRYPTOGRAPHY TEST SUITE")
    print("=" * 70)
    print()
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestKyber))
    suite.addTests(loader.loadTestsFromTestCase(TestChaCha20))
    suite.addTests(loader.loadTestsFromTestCase(TestSHA3))
    suite.addTests(loader.loadTestsFromTestCase(TestPoly1305))  # NEW
    suite.addTests(loader.loadTestsFromTestCase(TestNTT))  # NEW
    suite.addTests(loader.loadTestsFromTestCase(TestPerformance))  # NEW
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)