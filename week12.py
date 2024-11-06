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

# Inverse S-box for decryption
INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Complete Rijndael's Galois field multiplication table for MUL2
MUL2 = [
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
    0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
    0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
    0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
    0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
    0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
    0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
    0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
    0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
    0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
    0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
    0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
    0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
    0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
    0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
    0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5
]

class AES256:
    def __init__(self, key):
        self.rounds = 14  # AES-256 uses 14 rounds
        self.block_size = 16  # 128 bits
        self.key_size = 32   # 256 bits
        self.key = self._pad_key(key)
        self.round_keys = self._key_expansion()

    def _pad_key(self, key):
        if len(key) > self.key_size:
            return key[:self.key_size]
        return key.ljust(self.key_size, b'\0')

    def _sub_bytes(self, state):
        for i in range(4):
            for j in range(4):
                state[i][j] = SBOX[state[i][j]]
        return state

    def _shift_rows(self, state):
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
        return state

    def _mix_columns(self, state):
        for i in range(4):
            col = [state[j][i] for j in range(4)]
            col = self._mix_single_column(col)
            for j in range(4):
                state[j][i] = col[j]
        return state

    def _mix_single_column(self, col):
        temp = col[:]
        # Ensure all values are within valid range (0-255)
        col[0] = (MUL2[temp[0] % 256] ^ MUL2[temp[1] % 256] ^ temp[1] ^ temp[2] ^ temp[3]) % 256
        col[1] = (temp[0] ^ MUL2[temp[1] % 256] ^ MUL2[temp[2] % 256] ^ temp[2] ^ temp[3]) % 256
        col[2] = (temp[0] ^ temp[1] ^ MUL2[temp[2] % 256] ^ MUL2[temp[3] % 256] ^ temp[3]) % 256
        col[3] = (MUL2[temp[0] % 256] ^ temp[0] ^ temp[1] ^ temp[2] ^ MUL2[temp[3] % 256]) % 256
        return col

    def _add_round_key(self, state, round_key):
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]
        return state

    def _key_expansion(self):
        # Initialize round keys array with actual values instead of list comprehension
        round_keys = []
        for i in range(4 * (self.rounds + 1)):
            round_keys.append([0, 0, 0, 0])
        
        # First round key is the original key
        key_index = 0
        for i in range(8):
            for j in range(4):
                round_keys[i][j] = self.key[key_index]
                key_index += 1
        
        # Generate the rest of the round keys
        for i in range(8, 4 * (self.rounds + 1)):
            temp = round_keys[i-1].copy()
            
            if i % 8 == 0:
                # Rotate word
                temp = temp[1:] + temp[:1]
                # Apply S-box
                temp = [SBOX[b] for b in temp]
                # XOR with round constant
                temp[0] ^= (1 << ((i//8) - 1))
            elif i % 8 == 4:
                # Apply S-box
                temp = [SBOX[b] for b in temp]
                
            # XOR with word 8 positions earlier
            for j in range(4):
                round_keys[i][j] = round_keys[i-8][j] ^ temp[j]
        
        # Convert to 4x4 matrices for each round key
        final_round_keys = []
        for i in range(self.rounds + 1):
            key_matrix = [[0 for _ in range(4)] for _ in range(4)]
            for j in range(4):
                for k in range(4):
                    key_matrix[j][k] = round_keys[4*i + k][j]
            final_round_keys.append(key_matrix)
        
        return final_round_keys

    def _matrix_to_hex(self, matrix):
        """Convert a 4x4 matrix to a hex string in row-major order"""
        return ''.join(format(matrix[i][j], '02x') for j in range(4) for i in range(4))

    def encrypt(self, plaintext):
        state = self._text_to_matrix(plaintext)
        
        # Print initial input
        print(f"round[ 0].input {self._matrix_to_hex(state)}")
        print(f"round[ 0].k_sch {self._matrix_to_hex(self.round_keys[0])}")
        
        # Initial round
        state = self._add_round_key(state, self.round_keys[0])
        
        # Main rounds
        for round in range(1, self.rounds):
            print(f"round[{round:2d}].start {self._matrix_to_hex(state)}")
            
            state = self._sub_bytes(state)
            print(f"round[{round:2d}].s_box {self._matrix_to_hex(state)}")
            
            state = self._shift_rows(state)
            print(f"round[{round:2d}].s_row {self._matrix_to_hex(state)}")
            
            state = self._mix_columns(state)
            print(f"round[{round:2d}].m_col {self._matrix_to_hex(state)}")
            
            print(f"round[{round:2d}].k_sch {self._matrix_to_hex(self.round_keys[round])}")
            state = self._add_round_key(state, self.round_keys[round])
        
        # Final round (no mix columns)
        print(f"round[{self.rounds:2d}].start {self._matrix_to_hex(state)}")
        
        state = self._sub_bytes(state)
        print(f"round[{self.rounds:2d}].s_box {self._matrix_to_hex(state)}")
        
        state = self._shift_rows(state)
        print(f"round[{self.rounds:2d}].s_row {self._matrix_to_hex(state)}")
        
        print(f"round[{self.rounds:2d}].k_sch {self._matrix_to_hex(self.round_keys[self.rounds])}")
        state = self._add_round_key(state, self.round_keys[self.rounds])
        
        print(f"round[{self.rounds:2d}].output {self._matrix_to_hex(state)}")
        
        return self._matrix_to_text(state)

    def _text_to_matrix(self, text):
        matrix = [[0 for x in range(4)] for y in range(4)]
        for i in range(4):
            for j in range(4):
                matrix[i][j] = text[i + 4*j]
        return matrix

    def _matrix_to_text(self, matrix):
        text = []
        for i in range(4):
            for j in range(4):
                text.append(matrix[j][i])
        return bytes(text)

    def _inv_sub_bytes(self, state):
        for i in range(4):
            for j in range(4):
                state[i][j] = INV_SBOX[state[i][j]]
        return state

    def _inv_shift_rows(self, state):
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]
        return state

    def _inv_mix_columns(self, state):
        for i in range(4):
            col = [state[j][i] for j in range(4)]
            col = self._inv_mix_single_column(col)
            for j in range(4):
                state[j][i] = col[j]
        return state

    def _inv_mix_single_column(self, col):
        temp = col[:]
        col[0] = (gmul(temp[0], 0x0e) ^ gmul(temp[1], 0x0b) ^ 
                  gmul(temp[2], 0x0d) ^ gmul(temp[3], 0x09)) % 256
        col[1] = (gmul(temp[0], 0x09) ^ gmul(temp[1], 0x0e) ^ 
                  gmul(temp[2], 0x0b) ^ gmul(temp[3], 0x0d)) % 256
        col[2] = (gmul(temp[0], 0x0d) ^ gmul(temp[1], 0x09) ^ 
                  gmul(temp[2], 0x0e) ^ gmul(temp[3], 0x0b)) % 256
        col[3] = (gmul(temp[0], 0x0b) ^ gmul(temp[1], 0x0d) ^ 
                  gmul(temp[2], 0x09) ^ gmul(temp[3], 0x0e)) % 256
        return col

    def decrypt(self, ciphertext):
        state = self._text_to_matrix(ciphertext)
        
        # Print initial input
        print(f"round[ 0].iinput {self._matrix_to_hex(state)}")
        print(f"round[ 0].ik_sch {self._matrix_to_hex(self.round_keys[self.rounds])}")
        
        # Initial round
        state = self._add_round_key(state, self.round_keys[self.rounds])
        
        # Main rounds
        for round in range(self.rounds - 1, 0, -1):
            print(f"round[{self.rounds-round:2d}].istart {self._matrix_to_hex(state)}")
            
            state = self._inv_shift_rows(state)
            print(f"round[{self.rounds-round:2d}].is_row {self._matrix_to_hex(state)}")
            
            state = self._inv_sub_bytes(state)
            print(f"round[{self.rounds-round:2d}].is_box {self._matrix_to_hex(state)}")
            
            print(f"round[{self.rounds-round:2d}].ik_sch {self._matrix_to_hex(self.round_keys[round])}")
            state = self._add_round_key(state, self.round_keys[round])
            print(f"round[{self.rounds-round:2d}].ik_add {self._matrix_to_hex(state)}")
            
            state = self._inv_mix_columns(state)
            
        # Final round
        print(f"round[{self.rounds:2d}].istart {self._matrix_to_hex(state)}")
        
        state = self._inv_shift_rows(state)
        print(f"round[{self.rounds:2d}].is_row {self._matrix_to_hex(state)}")
        
        state = self._inv_sub_bytes(state)
        print(f"round[{self.rounds:2d}].is_box {self._matrix_to_hex(state)}")
        
        print(f"round[{self.rounds:2d}].ik_sch {self._matrix_to_hex(self.round_keys[0])}")
        state = self._add_round_key(state, self.round_keys[0])
        
        print(f"round[{self.rounds:2d}].output {self._matrix_to_hex(state)}")
        
        return self._matrix_to_text(state)

# Add this helper function at the top level
def gmul(a, b):
    """Galois Field multiplication for inverse mix columns"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b  # AES irreducible polynomial
        a &= 0xFF
        b >>= 1
    return p

def main():
    while True:
        print("\n" + "=" * 50)
        print("AES-256 Encryption/Decryption")
        print("=" * 50)
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '3':
            print("\nExiting program...")
            break
            
        if choice not in ['1', '2']:
            print("\nInvalid choice. Please try again.")
            continue
        
        try:
            if choice == '1':
                # Encryption
                print("\nEnter plaintext (32 hex characters):")
                print("Example: 00112233445566778899aabbccddeeff")
                text = input().strip()
                
                print("\nEnter key (64 hex characters):")
                print("Example: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                key = input().strip()
                
                # Validate and convert inputs
                text_bytes = bytes.fromhex(text)
                key_bytes = bytes.fromhex(key)
                
                if len(text_bytes) != 16:
                    print("Error: Plaintext must be exactly 16 bytes (32 hex characters)")
                    continue
                if len(key_bytes) != 32:
                    print("Error: Key must be exactly 32 bytes (64 hex characters)")
                    continue
                
                # Perform encryption
                aes = AES256(key_bytes)
                result = aes.encrypt(text_bytes)
                print(f"\nEncrypted (hex): {result.hex()}")
                
            else:
                # Decryption
                print("\nEnter ciphertext (32 hex characters):")
                text = input().strip()
                
                print("\nEnter key (64 hex characters):")
                print("Example: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                key = input().strip()
                
                # Validate and convert inputs
                text_bytes = bytes.fromhex(text)
                key_bytes = bytes.fromhex(key)
                
                if len(text_bytes) != 16:
                    print("Error: Ciphertext must be exactly 16 bytes (32 hex characters)")
                    continue
                if len(key_bytes) != 32:
                    print("Error: Key must be exactly 32 bytes (64 hex characters)")
                    continue
                
                # Perform decryption
                aes = AES256(key_bytes)
                result = aes.decrypt(text_bytes)
                print(f"\nDecrypted (hex): {result.hex()}")
                
        except ValueError as e:
            print(f"\nError: Invalid hex input - {str(e)}")
        except Exception as e:
            print(f"\nError: {str(e)}")

if __name__ == "__main__":
    main()