"""
Crypto logic for Reeder 3DES-EDE for USM (Internet draft).

https://tools.ietf.org/html/draft-reeder-snmpv3-usm-3desede-00
"""

from pysnmpcrypto import (
    CRYPTOGRAPHY,
    backend,
    generic_decrypt,
    generic_encrypt,
)


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.decrepit.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher, modes



def _cryptography_cipher(key, iv):
    """Build a cryptography TripleDES Cipher object.

    :param bytes key: Encryption key
    :param bytesiv iv: Initialization vector
    :returns: TripleDES Cipher instance
    :rtype: cryptography.hazmat.primitives.ciphers.Cipher
    """
    return Cipher(
        algorithm=algorithms.TripleDES(key),
        mode=modes.CBC(iv),
        backend=default_backend(),
    )


_CIPHER_FACTORY_MAP = {
    CRYPTOGRAPHY: _cryptography_cipher,
}


def encrypt(plaintext, key, iv):
    """Encrypt data using triple DES on the available backend.

    :param bytes plaintext: Plaintext data to encrypt
    :param bytes key: Encryption key
    :param bytes iv: Initialization vector
    :returns: Encrypted ciphertext
    :rtype: bytes
    """
    return generic_encrypt(_CIPHER_FACTORY_MAP, plaintext, key, iv)


def decrypt(ciphertext, key, iv):
    """Decrypt data using triple DES on the available backend.

    :param bytes ciphertext: Ciphertext data to decrypt
    :param bytes key: Encryption key
    :param bytes iv: Initialization vector
    :returns: Decrypted plaintext
    :rtype: bytes
    """
    return generic_decrypt(_CIPHER_FACTORY_MAP, ciphertext, key, iv)
