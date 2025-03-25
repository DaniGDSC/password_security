import time
import tracemalloc
import os
from datetime import datetime
from aes256 import AES256  # Import AES256 class from aes256.py

class PerformanceLogger:
    """Class to measure and log performance metrics"""
    
    def __init__(self, log_file="aes256_performance.log"):
        self.log_file = log_file
        self.clear_log()

    def clear_log(self):
        """Clear the log file if it exists"""
        if os.path.exists(self.log_file):
            open(self.log_file, 'w').close()

    def log(self, message):
        """Append message to log file with timestamp"""
        with open(self.log_file, 'a') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")

    def measure_performance(self, aes_instance, plaintext):
        """Measure and log performance metrics for encryption"""
        # Convert plaintext to bytes if it's a string
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()

        # Log input size
        input_size = len(plaintext)
        self.log(f"Input size: {input_size} bytes")

        # Measure key expansion time and memory
        tracemalloc.start()
        start_time = time.perf_counter()
        key_schedule = aes_instance._expand_key()
        key_exp_time = time.perf_counter() - start_time
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.log(f"Key Expansion - Time: {key_exp_time:.6f}s, Peak Memory: {peak / 1024:.2f} KB")

        # Measure single block encryption (16 bytes)
        block = plaintext[:16] if len(plaintext) >= 16 else aes_instance.pad(plaintext)[:16]
        tracemalloc.start()
        start_time = time.perf_counter()
        aes_instance.encrypt(block)
        block_time = time.perf_counter() - start_time
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.log(f"Single Block Encryption (16 bytes) - Time: {block_time:.6f}s, Peak Memory: {peak / 1024:.2f} KB")

        # Measure full encryption
        tracemalloc.start()
        start_time = time.perf_counter()
        ciphertext = aes_instance.encrypt_full(plaintext)
        full_time = time.perf_counter() - start_time
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        output_size = len(ciphertext)
        self.log(f"Full Encryption - Time: {full_time:.6f}s, Peak Memory: {peak / 1024:.2f} KB")
        self.log(f"Output size: {output_size} bytes")

        # Estimate time complexity
        blocks = (input_size + aes_instance.block_size - 1) // aes_instance.block_size
        self.log(f"Number of blocks: {blocks}")
        self.log(f"Estimated Time Complexity: O(n) where n is input size")
        self.log(f"Throughput: {input_size / full_time:.2f} bytes/second")

        return ciphertext

def main():
    # Initialize AES and logger
    key = b'12345678901234567890123456789012'
    aes = AES256(key)
    logger = PerformanceLogger()

    # Test with different input sizes
    test_cases = [
        "Short message",                     # < 16 bytes
        "Exactly 16 bytes here!!!",          # = 16 bytes
        "This is a much longer message that will require multiple blocks to encrypt"  # > 16 bytes
    ]

    for i, plaintext in enumerate(test_cases, 1):
        logger.log(f"\nTest Case {i}:")
        logger.log(f"Input: {plaintext}")
        ciphertext = logger.measure_performance(aes, plaintext)
        logger.log(f"Ciphertext (hex): {ciphertext.hex()}")
        logger.log("-" * 50)

    # Print log contents
    with open(logger.log_file, 'r') as f:
        print(f.read())

if __name__ == "__main__":
    main()