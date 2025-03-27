class AES256:
    # S-box
    SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    # Rcon lookup table
    RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    def __init__(self, key):
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("Key must be a 32-byte bytes object")
        self.key = key
        self.rounds = 14
        self.block_size = 16
        self.key_schedule = self._expand_key()

    def _expand_key(self):
        expanded = bytearray(self.key)
        for i in range(8, 60):
            temp = bytearray(expanded[-4:])
            if i % 8 == 0:
                temp = self._sub_word(self._rot_word(temp))
                temp[0] ^= self.RCON[i // 8]
            elif i % 8 == 4:
                temp = self._sub_word(temp)
            expanded.extend(bytes(a ^ b for a, b in zip(temp, expanded[-32:-28])))
        return bytes(expanded)

    def _sub_word(self, word):
        return bytearray(self.SBOX[b] for b in word)

    def _rot_word(self, word):
        return word[1:] + word[:1]

    def _add_round_key(self, state, round_key):
        return bytes(a ^ b for a, b in zip(state, round_key))

    def _sub_bytes(self, state):
        return bytes(self.SBOX[b] for b in state)

    def _shift_rows(self, state):
        s = list(state)
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
        return bytes(s)

    def _mix_columns(self, state):
        s = bytearray(state)
        for i in range(0, 16, 4):
            a, b, c, d = s[i:i + 4]
            s[i] = self._gf_mult(2, a) ^ self._gf_mult(3, b) ^ c ^ d
            s[i + 1] = a ^ self._gf_mult(2, b) ^ self._gf_mult(3, c) ^ d
            s[i + 2] = a ^ b ^ self._gf_mult(2, c) ^ self._gf_mult(3, d)
            s[i + 3] = self._gf_mult(3, a) ^ b ^ c ^ self._gf_mult(2, d)
        return bytes(s)

    def _gf_mult(self, a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            a = ((a << 1) ^ 0x1b) if a & 0x80 else a << 1
            b >>= 1
        return p & 0xff

    def encrypt(self, plaintext):
        if not isinstance(plaintext, bytes) or len(plaintext) != 16:
            raise ValueError("Plaintext must be a 16-byte bytes object")

        state = bytearray(plaintext)
        state = self._add_round_key(state, self.key_schedule[:16])

        for round in range(1, self.rounds):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self.key_schedule[round * 16:(round + 1) * 16])

        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.key_schedule[self.rounds * 16:(self.rounds + 1) * 16])

        return bytes(state)

    def pad(self, data):
        padding_len = self.block_size - (len(data) % self.block_size)
        return data + bytes([padding_len] * padding_len)

    def unpad(self, data):
        padding_len = data[-1]
        if padding_len > self.block_size or not all(p == padding_len for p in data[-padding_len:]):
            raise ValueError("Invalid padding")
        return data[:-padding_len]

    def encrypt_full(self, plaintext):
        plaintext = self.pad(plaintext)
        return b"".join(self.encrypt(plaintext[i:i + self.block_size]) for i in range(0, len(plaintext), self.block_size))


# Example usage
def main():
    key = b'12345678901234567890123456789012'
    aes = AES256(key)
    plaintext = input("Enter plaintext: ").encode()
    ciphertext = aes.encrypt_full(plaintext)
    print(f"Ciphertext (hex): {ciphertext.hex()}")


if __name__ == "__main__":
    main()
