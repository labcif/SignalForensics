# from Crypto.Hash import MD4
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import Hash, SHA256, SHA512, SHA1

####################### Cryptography #######################


# AES-256-GCM decryption
def aes_256_gcm_decrypt(key, nonce, ciphertext, tag):
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# AES-256-CBC encryption
def aes_256_cbc_decrypt(key, nonce, ciphertext):
    decryptor = Cipher(algorithms.AES(key), modes.CBC(nonce), backend=default_backend()).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# PBKDF2 key derivation
def pbkdf2_derive_key(algorithm, password, salt, iterations, key_length):
    kdf = PBKDF2HMAC(
        algorithm=algorithm, length=key_length, salt=salt, iterations=iterations, backend=default_backend()
    )
    return kdf.derive(password)


# Hashing algorithm
def hash_algorithm(data, algorithm, rounds=1):
    for _ in range(rounds):
        digest = Hash(algorithm, backend=default_backend())
        digest.update(data)
        data = digest.finalize()
    return data


# SHA-256 hash
def hash_sha256(data, rounds=1):
    return hash_algorithm(data, SHA256(), rounds)


# SHA-512 hash
def hash_sha512(data, rounds=1):
    return hash_algorithm(data, SHA512(), rounds)


# SHA-1 hash
def hash_sha1(data, rounds=1):
    return hash_algorithm(data, SHA1(), rounds)


# MD4 hash
# def hash_md4(data):
#    return MD4.new(data).digest()


# def hash_from_alg_id(data, alg_id, rounds=1):
#    if alg_id == 32780:
#        return hash_sha256(data, rounds)
#    elif alg_id == 32782:
#        return hash_sha512(data, rounds)
#    else:
#        raise ValueError(f"Unsupported hash algorithm ID: {alg_id}")


def get_hash_algorithm(alg_id):
    if alg_id == 32780:
        return SHA256()
    elif alg_id == 32782:
        return SHA512()
    else:
        raise ValueError(f"Unsupported hash algorithm ID: {alg_id}")
