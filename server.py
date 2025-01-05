import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Key exchange function
def key_exchange():
    private_key_a = ec.generate_private_key(ec.SECP256R1())
    private_key_b = ec.generate_private_key(ec.SECP256R1())
    public_key_a = private_key_a.public_key()
    public_key_b = private_key_b.public_key()

    shared_secret_a = private_key_a.exchange(ec.ECDH(), public_key_b)
    shared_secret_b = private_key_b.exchange(ec.ECDH(), public_key_a)

    assert shared_secret_a == shared_secret_b, "Shared secrets do not match!"
    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'chaotic-encryption'
    ).derive(shared_secret_a)

    return symmetric_key

def decrypt_audio(encrypted_data, aes_key, chacha_key):
    chacha_nonce = encrypted_data[:16]
    chacha_encrypted_data = encrypted_data[16:]

    chacha_cipher = Cipher(algorithms.ChaCha20(chacha_key, chacha_nonce), mode=None)
    chacha_decryptor = chacha_cipher.decryptor()
    aes_encrypted_data = chacha_decryptor.update(chacha_encrypted_data)

    aes_iv = aes_encrypted_data[:16]
    aes_ciphertext = aes_encrypted_data[16:]

    aes_cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv))
    aes_decryptor = aes_cipher.decryptor()
    decrypted_data = aes_decryptor.update(aes_ciphertext) + aes_decryptor.finalize()

    return decrypted_data

    private_key_a = ec.generate_private_key(ec.SECP256R1())
    private_key_b = ec.generate_private_key(ec.SECP256R1())
    public_key_a = private_key_a.public_key()
    public_key_b = private_key_b.public_key()
    shared_secret_a = private_key_a.exchange(ec.ECDH(), public_key_b)
    shared_secret_b = private_key_b.exchange(ec.ECDH(), public_key_a)
    assert shared_secret_a == shared_secret_b, "Shared secrets do not match!"
    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'chaotic-encryption'
    ).derive(shared_secret_a)
    return symmetric_key

# Hybrid chaotic map function
def hybrid_chaotic_map(seed, size=256):
    sequence = []
    x = seed % 1.0
    y = (seed * 1.5) % 1.0
    for _ in range(size):
        x = 4 * x * (1 - x)
        x = max(min(x, 1.0), 0.0)
        a, b = 1.4, 0.3
        x_henon = 1 - a * x ** 2 + y
        y = b * x
        x_henon = max(min(x_henon, 1.0), 0.0)
        x = x_henon
        combined_value = x * y
        sequence.append(combined_value)
    chaotic_key = hashes.Hash(hashes.SHA256())
    for value in sequence:
        chaotic_key.update(str(value).encode())
    return chaotic_key.finalize()

# Decryption function
    chacha_nonce = encrypted_data[:16]
    chacha_encrypted_data = encrypted_data[16:]
    chacha_cipher = Cipher(algorithms.ChaCha20(chacha_key, chacha_nonce), mode=None)
    chacha_decryptor = chacha_cipher.decryptor()
    aes_encrypted_data = chacha_decryptor.update(chacha_encrypted_data)
    aes_iv = aes_encrypted_data[:16]
    aes_ciphertext = aes_encrypted_data[16:]
    aes_cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv))
    aes_decryptor = aes_cipher.decryptor()
    decrypted_data = aes_decryptor.update(aes_ciphertext) + aes_decryptor.finalize()
    return decrypted_data

# Write audio file function
def write_audio_file(file_path, data):
    with open(file_path, 'wb') as f:
        f.write(data)

# Server function
def server():
    host = '0.0.0.0'
    port = 12345
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}")
    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}")
    encrypted_audio = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        encrypted_audio += chunk
    print("Encrypted audio received. Starting decryption...")
    symmetric_key = key_exchange()
    chaotic_key = hybrid_chaotic_map(sum(bytearray(symmetric_key)))
    decrypted_audio = decrypt_audio(encrypted_audio, symmetric_key, chaotic_key)
    decrypted_audio_path = "decrypted_audio_server.mp3"
    write_audio_file(decrypted_audio_path, decrypted_audio)
    print(f"Decrypted audio saved to {decrypted_audio_path}")
    conn.close()
    server_socket.close()

if __name__ == "__main__":
    server()
