import random
from hashlib import sha256

def feistel_block_encrypt(block, keys):
    # Split the block into two halves
    left, right = block[:len(block)//2], block[len(block)//2:]
    # Perform the Feistel rounds
    for key in keys:
        new_right = left
        left = right
        right = xor(new_right, feistel_function(left, right))
    # Return the encrypted block
    return left + right

def feistel_block_decrypt(block, keys):
    # Split the block into two halves
    left, right = block[:len(block)//2], block[len(block)//2:]
    # Perform the Feistel rounds
    for key in reversed(keys):
        new_right = left
        left = right
        right = xor(new_right, feistel_function(left, right))
    # Return the encrypted block
    return left + right

def feistel_function(block,key):
    # Combine the block and key, hash the result and truncate to block size
    combined = xor(block,key) + key
    hashed = sha256(combined).digest()
    return hashed[:len(block)]

def xor(block,key):
    # Repeat the key to match the block size and perform XOR
    key_repeated = key * (len(block) // len(key)) + key[:len(block) % len(key)]
    return bytes(a^b for a,b in zip(block, key_repeated))

def generate_keys(master_key, num_rounds):
    # Derive a series of round keys from the master key
    keys = []
    current_key = master_key
    for _ in range(num_rounds):
        current_key = sha256(current_key).digest()
        keys.append(current_key)
    return keys

# Running An example
# Parameters Initializaation, key generation
master_key = b'secure_key'
num_rounds = 25
keys = generate_keys(master_key, num_rounds)
# Define the plaintext for encrypting
plain_text = b'secret_message'
# Ensure the plaintext is the right length for simplicity
'''
Notes: 
In case below, we pad the plain_text with the null byte b'\0' 
until the total length of the string is 32 bytes.
'''
plain_text = plain_text.ljust(32,b'\0')
# Implement Feistel encryption
cipher_text = feistel_block_encrypt(plain_text, keys)
print(f'Cipher text in hex: {cipher_text}')

