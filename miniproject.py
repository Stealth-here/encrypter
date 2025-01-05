from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def key_exchange():
    """
    Perform ECDH key exchange and derive a symmetric key.
    """
    # Generate private-public key pairs
    private_key_a = ec.generate_private_key(ec.SECP256R1())
    private_key_b = ec.generate_private_key(ec.SECP256R1())
    public_key_a = private_key_a.public_key()
    public_key_b = private_key_b.public_key()

    # Derive shared secrets
    shared_secret_a = private_key_a.exchange(ec.ECDH(), public_key_b)
    shared_secret_b = private_key_b.exchange(ec.ECDH(), public_key_a)

    # Verify shared secrets match
    assert shared_secret_a == shared_secret_b, "Shared secrets do not match!"

    # Derive symmetric key
    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'chaotic-encryption'
    ).derive(shared_secret_a)

    print(f"Symmetric Key: {symmetric_key.hex()}")
    return symmetric_key


def hybrid_chaotic_map(seed, size=256):
    """
    Generate a chaotic key using a hybrid system of logistic and Henon maps.
    """
    sequence = []
    x = seed % 1.0  # Ensure seed is in [0, 1) for logistic map
    y = (seed * 1.5) % 1.0  # Initialize Henon map parameter

    for _ in range(size):
        # Logistic map equation
        x = 4 * x * (1 - x)
        # Henon map equations
        a, b = 1.4, 0.3
        x_henon = 1 - a * x ** 2 + y
        y = b * x
        x = x_henon

        # Combine values from both maps
        combined_value = x * y
        sequence.append(combined_value)

    # Hash the sequence into a 256-bit key
    chaotic_key = hashes.Hash(hashes.SHA256())
    for value in sequence:
        chaotic_key.update(str(value).encode())

    final_key = chaotic_key.finalize()
    print(f"Hybrid Chaotic Key: {final_key.hex()}")
    return final_key

def encrypt_audio(data, aes_key, chacha_key):
    """
    Encrypt audio data using AES in CFB mode followed by ChaCha20.
    """
    # First Layer: AES in CFB mode
    aes_iv = os.urandom(16)
    aes_cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv))
    aes_encryptor = aes_cipher.encryptor()
    aes_encrypted_data = aes_iv + aes_encryptor.update(data) + aes_encryptor.finalize()

    # Second Layer: ChaCha20
    chacha_nonce = os.urandom(16)
    chacha_cipher = Cipher(algorithms.ChaCha20(chacha_key, chacha_nonce), mode=None)
    chacha_encryptor = chacha_cipher.encryptor()
    final_encrypted_data = chacha_nonce + chacha_encryptor.update(aes_encrypted_data)

    print(f"AES IV: {aes_iv.hex()}")
    print(f"ChaCha20 Nonce: {chacha_nonce.hex()}")
    return final_encrypted_data
def decrypt_audio(encrypted_data, aes_key, chacha_key):
    """
    Decrypt audio data encrypted with AES and ChaCha20.
    """
    # Extract ChaCha20 nonce
    chacha_nonce = encrypted_data[:16]
    chacha_encrypted_data = encrypted_data[16:]

    # Decrypt using ChaCha20
    chacha_cipher = Cipher(algorithms.ChaCha20(chacha_key, chacha_nonce), mode=None)
    chacha_decryptor = chacha_cipher.decryptor()
    aes_encrypted_data = chacha_decryptor.update(chacha_encrypted_data)

    # Extract AES IV
    aes_iv = aes_encrypted_data[:16]
    aes_ciphertext = aes_encrypted_data[16:]

    # Decrypt using AES in CFB mode
    aes_cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv))
    aes_decryptor = aes_cipher.decryptor()
    decrypted_data = aes_decryptor.update(aes_ciphertext) + aes_decryptor.finalize()

    return decrypted_data
def read_audio_file(file_path):
    """
    Read binary data from an audio file.
    """
    with open(file_path, 'rb') as f:
        return f.read()

def write_audio_file(file_path, data):
    """
    Write binary data to an audio file.
    """
    with open(file_path, 'wb') as f:
        f.write(data)


if __name__ == "__main__":
    # File paths
    input_audio_path = "sample_audio.mp3"
    encrypted_audio_path = "encrypted_audio.enc"
    decrypted_audio_path = "decrypted_audio.mp3"

    # Read input audio file
    audio_data = read_audio_file(input_audio_path)

    # Perform key exchange
    symmetric_key = key_exchange()

    # Generate chaotic key using a hybrid chaotic map
    chaotic_key = hybrid_chaotic_map(sum(bytearray(symmetric_key)))

    # Encrypt audio with multi-layer encryption
    encrypted_audio = encrypt_audio(audio_data, symmetric_key, chaotic_key)
    write_audio_file(encrypted_audio_path, encrypted_audio)
    print(f"Encrypted audio saved to {encrypted_audio_path}")

    # Decrypt audio with multi-layer decryption
    decrypted_audio = decrypt_audio(encrypted_audio, symmetric_key, chaotic_key)
    write_audio_file(decrypted_audio_path, decrypted_audio)
    print(f"Decrypted audio saved to {decrypted_audio_path}")