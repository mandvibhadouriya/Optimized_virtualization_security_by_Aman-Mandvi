import base64
# PRESENT S-Box
SBox = (
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
)

# PRESENT bit-permutation
PBox = [
    0, 16, 32, 48, 1, 17, 33, 49,
    2, 18, 34, 50, 3, 19, 35, 51,
    4, 20, 36, 52, 5, 21, 37, 53,
    6, 22, 38, 54, 7, 23, 39, 55,
    8, 24, 40, 56, 9, 25, 41, 57,
    10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61,
    14, 30, 46, 62, 15, 31, 47, 63
]

# Key Schedule Generation
def key_schedule(key):
    round_keys = [key]
    for i in range(31):
        key = (key << 61) ^ (key >> 19)
        key = (SBox[(key >> 60) & 0xF] << 60) | (key & 0xFFFFFFFFFFFFFFF)
        round_keys.append(key)
    return round_keys

# Encryption
def present_encrypt(plaintext, round_keys):
    state = plaintext
    for i in range(31):
        state = state ^ round_keys[i]
        print(f"Round {i + 1} (Subkey {i}): 0x{state:016X}")

        # Apply bit permutation
        state = apply_pbox(state)
        print(f"Round {i + 1} (Permutation): 0x{state:016X}")

    # Final round
    state = state ^ round_keys[31]
    print(f"Round 32 (Subkey 31): 0x{state:016X}")

    return state

# Decryption
def present_decrypt(ciphertext, round_keys):
    state = ciphertext

    # Inverse of the final round
    state = state ^ round_keys[31]
    print(f"Inverse of Round 32 (Subkey 31): 0x{state:016X}")

    for i in range(31, 0, -1):
        # Inverse of the permutation
        state = apply_inverse_pbox(state)
        print(f"Inverse of Round {i} (Permutation): 0x{state:016X}")

        state = state ^ round_keys[i]
        print(f"Inverse of Round {i} (Subkey {i}): 0x{state:016X}")

    return state

# Function to apply bit permutation
def apply_pbox(state):
    result = 0
    for i, bit_position in enumerate(PBox):
        if state & (1 << i):
            result |= 1 << bit_position
    return result

# Function to apply inverse of bit permutation
def apply_inverse_pbox(state):
    result = 0
    for i, bit_position in enumerate(PBox):
        if state & (1 << bit_position):
            result |= 1 << i
    return result

def encrypt_and_decrypt_text(text, key):
    # Encode text as Base64 before encryption
    encoded_text = base64.b64encode(text.encode('utf-8'))

    # Convert Base64-encoded data to an integer
    plaintext_int = int.from_bytes(encoded_text, byteorder='big')

    # Encrypt the integer
    ciphertext_int = present_encrypt(plaintext_int, key)

    # Decrypt the integer
    decrypted_int = present_decrypt(ciphertext_int, key)

    # Convert the decrypted integer back to binary data
    decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big')

    # Decode the binary data from Base64 to get the original text
    decrypted_text = base64.b64decode(decrypted_bytes).decode('utf-8')

    return decrypted_text

# Example usage
plaintext = "Hello, this is an example."
key = 0x00112233445566778899AABBCCDDEEFF
round_keys = key_schedule(key)

print("Original Text:", plaintext)
decrypted_text = encrypt_and_decrypt_text(plaintext, round_keys)
print("Decrypted Text:", decrypted_text)
