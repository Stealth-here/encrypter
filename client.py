import socket
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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

def encrypt_audio(data, aes_key, chacha_key):
    # AES encryption
    aes_iv = os.urandom(16)
    aes_cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv))
    aes_encryptor = aes_cipher.encryptor()
    aes_encrypted_data = aes_iv + aes_encryptor.update(data) + aes_encryptor.finalize()

    # ChaCha20 encryption
    chacha_nonce = os.urandom(16)
    chacha_cipher = Cipher(algorithms.ChaCha20(chacha_key, chacha_nonce), mode=None)
    chacha_encryptor = chacha_cipher.encryptor()
    final_encrypted_data = chacha_nonce + chacha_encryptor.update(aes_encrypted_data)

    return final_encrypted_data

def client(audio_file):
    with open(audio_file, 'rb') as f:
        audio_data = f.read()

    symmetric_key = key_exchange()

    # Generate a proper 32-byte ChaCha20 key
    chacha_key = symmetric_key[:32]  # Use the first 32 bytes of symmetric_key

    encrypted_audio = encrypt_audio(audio_data, symmetric_key, chacha_key)

    server_address = ('127.0.0.1', 12345)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(server_address)
        s.sendall(encrypted_audio)
        print("Encrypted audio sent to server.")

if __name__ == "__main__":
    client('sample_audio.mp3')
