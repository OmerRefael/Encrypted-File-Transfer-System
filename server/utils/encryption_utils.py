from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


AES_KEY_SIZE = 256 // 8  # 256 bits key size


def generate_aes_key() -> bytes:
    """
    Generate a random AES key.

    Returns:
        bytes: A random AES key.
    """
    return get_random_bytes(AES_KEY_SIZE)


def encrypt_by_public_key(public_key: bytes, data: bytes) -> bytes:
    """
    Encrypt the data using the public key
    Args:
        public_key (bytes): The public key used for encryption.
        data (bytes): The data to encrypt.

    Returns:
        bytes: The encrypted data.
    """
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(data)


def decrypt_by_aes_key(aes_key: bytes, data: bytes) -> bytes:
    """
    Decrypt the data using the AES key

    Args:
        aes_key (bytes): The AES key used for decryption.
        data (bytes): The data to decrypt.

    Returns:
        bytes: The decrypted data.
    """
    iv = b'\x00' * AES.block_size
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(data), AES.block_size)
    return plaintext
