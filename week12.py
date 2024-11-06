# AES constants
AES_BLOCK_SIZE = 16
Nk = 8  # Number of 32-bit words in the key for AES-256
Nr = 14  # Number of rounds for AES-256
Nb = 4  # Number of columns (32-bit words) in the state

# S-box and Inverse S-box
sbox = [
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


inv_sbox = [
   0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
   0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
   0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
   0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
   0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
   0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
   0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x6f,
   0x01, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21,
   0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
   0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
   0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62,
   0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea,
   0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
   0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
   0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9,
   0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f
]


# Round Constant array
rcon = [
   0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
   0x6c, 0xd8, 0xab, 0x4d, 0x9a  # Added more constants for AES-256
]


def create_matrix(data):
    """Convert a 16-byte array into a 4x4 matrix"""
    matrix = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            matrix[i][j] = data[4*j + i]
    return matrix

def matrix_to_list(matrix):
    """Convert a 4x4 matrix into a 16-byte array"""
    result = []
    for j in range(4):
        for i in range(4):
            result.append(matrix[i][j])
    return result

def key_expansion(key):
    """Key expansion for AES-256"""
    # Initialize key schedule array
    w = [[0] * 4 for _ in range(60)]  # 60 = Nb * (Nr + 1)
    
    # First Nk words are the original key
    for i in range(Nk):
        w[i] = [key[4*i], key[4*i + 1], key[4*i + 2], key[4*i + 3]]
    
    # Generate the rest of the key schedule
    for i in range(Nk, 4 * (Nr + 1)):  # 4 * (Nr + 1) = 60 for AES-256
        temp = w[i-1][:]
        
        if i % Nk == 0:
            # RotWord
            temp = temp[1:] + [temp[0]]
            # SubWord
            temp = [sbox[b] for b in temp]
            # XOR with round constant
            temp[0] ^= rcon[i // Nk - 1]
        elif Nk > 6 and i % Nk == 4:
            # Additional S-box for AES-256
            temp = [sbox[b] for b in temp]
        
        # XOR with word Nk positions earlier
        w[i] = [w[i-Nk][j] ^ temp[j] for j in range(4)]
    
    # Convert to the format needed by encryption function
    key_schedule = [[0 for _ in range(4 * (Nr + 1))] for _ in range(4)]
    for i in range(4 * (Nr + 1)):
        for j in range(4):
            key_schedule[j][i] = w[i][j]
    
    return key_schedule

def add_round_key(state, round_key):
    """XOR state with round key"""
    new_state = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            new_state[i][j] = state[i][j] ^ round_key[i][j]
    return new_state

def sub_bytes(state):
    """Apply S-box substitution to each byte in the state matrix"""
    new_state = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            new_state[i][j] = sbox[state[i][j]]
    return new_state

def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = inv_sbox[state[i][j]]
    return state

def shift_rows(state):
    """ShiftRows transformation"""
    new_state = [[0 for _ in range(4)] for _ in range(4)]
    
    # Row 0: no shift
    new_state[0] = state[0][:]
    
    # Row 1: shift left by 1
    new_state[1] = state[1][1:] + state[1][:1]
    
    # Row 2: shift left by 2
    new_state[2] = state[2][2:] + state[2][:2]
    
    # Row 3: shift left by 3
    new_state[3] = state[3][3:] + state[3][:3]
    
    return new_state

def inv_shift_rows(state):
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]
    return state

def galois_mult(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xff
        if high_bit:
            a ^= 0x1b
        b >>= 1
    return p

def mix_columns(state):
    for i in range(4):
        t = state[i][:]
        state[i][0] = galois_mult(t[0], 2) ^ galois_mult(t[1], 3) ^ t[2] ^ t[3]
        state[i][1] = t[0] ^ galois_mult(t[1], 2) ^ galois_mult(t[2], 3) ^ t[3]
        state[i][2] = t[0] ^ t[1] ^ galois_mult(t[2], 2) ^ galois_mult(t[3], 3)
        state[i][3] = galois_mult(t[0], 3) ^ t[1] ^ t[2] ^ galois_mult(t[3], 2)
    return state

def inv_mix_columns(state):
    for i in range(4):
        t = state[i][:]
        state[i][0] = galois_mult(t[0], 0x0e) ^ galois_mult(t[1], 0x0b) ^ galois_mult(t[2], 0x0d) ^ galois_mult(t[3], 0x09)
        state[i][1] = galois_mult(t[0], 0x09) ^ galois_mult(t[1], 0x0e) ^ galois_mult(t[2], 0x0b) ^ galois_mult(t[3], 0x0d)
        state[i][2] = galois_mult(t[0], 0x0d) ^ galois_mult(t[1], 0x09) ^ galois_mult(t[2], 0x0e) ^ galois_mult(t[3], 0x0b)
        state[i][3] = galois_mult(t[0], 0x0b) ^ galois_mult(t[1], 0x0d) ^ galois_mult(t[2], 0x09) ^ galois_mult(t[3], 0x0e)
    return state

def aes_encrypt(plaintext, key):
    """AES encryption function"""
    state = create_matrix(plaintext)
    key_schedule = key_expansion(key)
    
    # Initial round
    print(f"round[ 0].input {''.join([hex(b)[2:].zfill(2) for b in matrix_to_list(state)])}")
    initial_round_key = [[key_schedule[i][j] for j in range(4)] for i in range(4)]
    print(f"round[ 0].k_sch {''.join([hex(b)[2:].zfill(2) for b in matrix_to_list(initial_round_key)])}")
    
    state = add_round_key(state, initial_round_key)

    # Main rounds
    for round in range(1, Nr):
        print(f"round[{round:2d}].start {''.join([hex(b)[2:].zfill(2) for b in matrix_to_list(state)])}")
        state = sub_bytes(state)
        print(f"round[{round:2d}].s_box {''.join([hex(b)[2:].zfill(2) for b in matrix_to_list(state)])}")
        state = shift_rows(state)
        print(f"round[{round:2d}].s_row {''.join([hex(b)[2:].zfill(2) for b in matrix_to_list(state)])}")
        state = mix_columns(state)
        print(f"round[{round:2d}].m_col {''.join([hex(b)[2:].zfill(2) for b in matrix_to_list(state)])}")
        
        round_key = [[key_schedule[i][j] for j in range(4*round, 4*(round+1))] for i in range(4)]
        state = add_round_key(state, round_key)
        print(f"round[{round:2d}].k_sch {''.join([hex(b)[2:].zfill(2) for b in matrix_to_list(round_key)])}")

    # Final round
    print(f"round[{Nr}].start {''.join([hex(b)[2:].zfill(2) for b in matrix_to_list(state)])}")
    
    # SubBytes
    state = sub_bytes(state)
    print(f"round[{Nr}].s_box {''.join([hex(b)[2:].zfill(2) for b in matrix_to_list(state)])}")
    
    # ShiftRows
    state = shift_rows(state)
    print(f"round[{Nr}].s_row {''.join([hex(b)[2:].zfill(2) for b in matrix_to_list(state)])}")
    
    # AddRoundKey with final round key
    final_round_key = [
        [key_schedule[row][4*Nr + col] for col in range(4)]
        for row in range(4)
    ]
    state = add_round_key(state, final_round_key)
    
    # Print final round key and output
    print(f"round[{Nr}].k_sch {''.join([hex(b)[2:].zfill(2) for b in matrix_to_list(final_round_key)])}")
    print(f"round[{Nr}].output {''.join([hex(b)[2:].zfill(2) for b in matrix_to_list(state)])}")

    return matrix_to_list(state)

def hex_string_to_bytes(hex_string):
    """Convert hex string to list of bytes"""
    return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]

def main():
    # Get input from user
    print("Enter plaintext and key in hexadecimal format (without '0x' prefix)")
    plaintext_hex = input("PLAINTEXT: ").strip()
    key_hex = input("KEY: ").strip()
    
    try:
        # Convert hex strings to byte lists
        plaintext = hex_string_to_bytes(plaintext_hex)
        key = hex_string_to_bytes(key_hex)
        
        # Verify input lengths
        if len(plaintext) != 16:
            raise ValueError("Plaintext must be 16 bytes (32 hex characters)")
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes (64 hex characters)")
            
        print("CIPHER (ENCRYPT):")
        ciphertext = aes_encrypt(plaintext, key)
        
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
