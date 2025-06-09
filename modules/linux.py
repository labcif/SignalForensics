from modules.shared_utils import log, MalformedKeyError, bytes_to_hex
from modules.crypto import aes_cbc_decrypt, pbkdf2_derive_key
from cryptography.hazmat.primitives.hashes import SHA1

DEC_KEY_PREFIX_HARDCODED = "v10"
DEC_KEY_PREFIX_W_LIB = "v11"
LINUX_HARDCODED_KEY = b"peanuts"


def get_linux_hardcoded_key() -> bytes:
    return LINUX_HARDCODED_KEY


# V10 = yes, V11 = no
def linux_should_use_hardcoded_key(sqlcipher_key_cipherdata: bytes) -> bool:
    """
    Determines whether to use the hardcoded key based on the version.
    """
    if sqlcipher_key_cipherdata[: len(DEC_KEY_PREFIX_HARDCODED)] == DEC_KEY_PREFIX_HARDCODED.encode("utf-8"):
        log("Using hardcoded key for SQLCipher key decryption...", 3)
        return True
    elif sqlcipher_key_cipherdata[: len(DEC_KEY_PREFIX_W_LIB)] == DEC_KEY_PREFIX_W_LIB.encode("utf-8"):
        return False
    else:
        raise MalformedKeyError("The encrypted SQLCipher key does not start with one of the expected prefixes.")


def linux_derive_aux_key(passphrase: bytes) -> bytes:
    log("Deriving the auxiliary key...", 2)
    aux_key = pbkdf2_derive_key(algorithm=SHA1(), password=passphrase, salt=b"saltysalt", iterations=1, key_length=16)

    return aux_key


def linux_get_sqlcipher_key_from_aux(encrypted_key: bytes, aux_key: bytes) -> bytes:
    # log(f"> Encrypted SQLCipher Key: {bytes_to_hex(encrypted_key)}", 3)

    log("Decrypting the SQLCipher key...", 2)
    log(f"> Auxiliary Key: {bytes_to_hex(aux_key)}", 3)
    log(f"> Encrypted Key: {bytes_to_hex(encrypted_key)}", 3)
    return aes_cbc_decrypt(aux_key, b" " * 16, encrypted_key)[:64]
