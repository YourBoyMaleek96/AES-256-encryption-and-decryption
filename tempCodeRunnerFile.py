 1
    return p % 256

# AES Encryption
# AES Encryption with round print statements
def aes_encrypt(plaintext, key):
    state = np.array(list(plaintext), dtype=np.uint8).reshape(4, 4)
    key_schedule = key_expansion(key)
    
    print(f"round[ 0].input {[hex(b) for b in state.flatten().tolist()]}")
    print(f"round[ 0].k_sch {[hex(b) for b in key_schedule[:4, :].flatten().tolist()]}")
    
    state = add_round_key(state, key_schedule[:4, :])

    for round in range(1, Nr):
        print(f"round[ {round}].start {[hex(b) for b in state.flatten().tolist()]}")
        state = sub_bytes(state)
        print(f"round[ {round}].s_box {[hex(b) for b in state.flatten().tolist()]}")
        state = shift_rows(state)
        print(f"round[ {round}].s_row {[hex(b) for b in state.flatten().tolist()]}")
        state = mix_columns(state)
        print(f"round[ {round}].m_col {[hex(b) for b in state.flatten().tolist()]}")
        state = add_round_key(state, key_schedule[round * 4:(round + 1) * 4])
        print(f"round[ {round}].k_sch {[hex(b) for b in key_schedule[round * 4:(round + 1) * 4].flatten().tolist()]}")

    print(f"round[{Nr}].start {[hex(b) for b in state.flatten().tolist()]}")
    state = sub_bytes(state)
    print(f"round[{Nr}].s_box {[hex(b) for b in state.flatten().tolist()]}")
    state = shift_rows(state)
    print(f"round[{Nr}].s_row {[hex(b) for b in state.flatten().tolist()]}")
    state = add_round_key(state, key_schedule[Nr * 4:(Nr + 1) * 4])
    print(f"round[{Nr}].k_sch {[hex(b) for b in key_schedule[Nr * 4:(Nr + 1) * 4].flatten().tolist()]}")

    return state.flatten()
# Hardcoded plaintext and key
plaintext = [
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff
]

key = [
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f
]
ciphertext = aes_encrypt(plaintext, key)
print(f"round[{Nr}].output {[hex(b) for b in ciphertext.tolist()]}")