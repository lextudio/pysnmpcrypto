"""
Crypto logic for RFC3826.

https://tools.ietf.org/html/rfc3826
"""
from pysnmpcrypto import (
    backend, CRYPTOGRAPHY, generic_decrypt, generic_encrypt)

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes


def _cryptography_cipher(key, iv):
    """Build a cryptography AES Cipher object.

    :param bytes key: Encryption key
    :param bytes iv: Initialization vector
    :returns: AES Cipher instance
    :rtype: cryptography.hazmat.primitives.ciphers.Cipher
    """
    return Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.CFB(iv),
        backend=default_backend()
    )


_CIPHER_FACTORY_MAP = {
    CRYPTOGRAPHY: _cryptography_cipher,
}


def encrypt(plaintext, key, iv):
    """Encrypt data using AES on the available backend.

    :param bytes plaintext: Plaintext data to encrypt
    :param bytes key: Encryption key
    :param bytes iv: Initialization vector
    :returns: Encrypted ciphertext
    :rtype: bytes
    """
    return generic_encrypt(_CIPHER_FACTORY_MAP, plaintext, key, iv)


def decrypt(ciphertext, key, iv):
    """Decrypt data using AES on the available backend.

    :param bytes ciphertext: Ciphertext data to decrypt
    :param bytes key: Encryption key
    :param bytes iv: Initialization vector
    :returns: Decrypted plaintext
    :rtype: bytes
    """
    return generic_decrypt(_CIPHER_FACTORY_MAP, ciphertext, key, iv)
