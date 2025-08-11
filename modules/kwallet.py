from modules.crypto import blowfish_cbc_decrypt, blowfish_ecb_decrypt, pbkdf2_derive_key
from modules.shared_utils import bytes_to_hex, log, skip_string
from cryptography.hazmat.primitives.hashes import SHA512
import pathlib
import struct
from modules.linux import (
    linux_get_sqlcipher_key_from_aux,
    linux_derive_aux_key,
)

KW_MAGIC = b"KWALLET\n\r\0\r\n"
CIPHER_BF_ECB = 0x00
CIPHER_GPG = 0x02
CIPHER_BF_CBC = 0x03
CHROMIUM_BYTE_SEQ_1 = bytes.fromhex("E8463316D20BAD7A467DCDF13E90501B")  # MD5 of "Chromium Keys"
CHROMIUM_BYTE_SEQ_2 = bytes.fromhex("020B448388EF0BA44BC6C8542DE42692")  # MD5 of Chromium Safe Storage
CHROMIUM_BYTE_SEQ_3 = bytes.fromhex(
    "4300680072006F006D00690075006D00200053006100660065002000530074006F0072006100670065"
)

DEC_KEY_PREFIX_KWALLET = "v11"


# Process a KWallet file (KWF) and extract the encrypted data
def process_kwallet_file(kwallet_path: pathlib.Path):
    if not kwallet_path.is_file():
        raise FileNotFoundError(f"KWallet file '{kwallet_path}' does not exist.")

    with kwallet_path.open("rb") as f:
        data = f.read()

    log(f"Processing KWallet file...", 2)

    # Check if the file prefix is correct
    idx = len(KW_MAGIC)
    if data[:idx] != KW_MAGIC:
        raise ValueError("Invalid KWallet file format.")

    cipher = data[idx + 2]
    hash = data[idx + 3]
    idx += 4

    if cipher not in [CIPHER_BF_CBC, CIPHER_GPG, CIPHER_BF_ECB]:
        raise ValueError(f"Unexpected cipher signature (0x{bytes_to_hex(cipher)}) found in the KWallet file.")

    if cipher == CIPHER_BF_CBC or cipher == CIPHER_BF_ECB:
        if CHROMIUM_BYTE_SEQ_1 not in data or CHROMIUM_BYTE_SEQ_2 not in data:
            raise ValueError(
                f"KWallet does not contain the expected MD5 hashes. Either the KWallet file is corrupted or it does not contain the required passphrase to derive Signal Desktop's auxiliary key."
            )

    if cipher == CIPHER_GPG:
        raise NotImplementedError("GPG support is not implemented yet. Can not process KWallet file with GPG cipher.")

    if hash != 0x02:
        log(f"[!] KWallet file claims to not use the KDF SignalForensic supports. Errors are expected.")
        log(f"[!] KDF signature: 0x{bytes_to_hex(hash)} (expected is 0x02 for PBKDF2-SHA512)")

    log(f"> Cipher: {cipher}, Hash: {hash}", 3)

    # Get the folder count
    folder_count = struct.unpack(">I", data[idx : idx + 4])[0]
    idx += 4

    log("Skipping non-essential data...", 3)

    for _ in range(folder_count):
        # Skip folder name hash
        idx += 16

        # Get entry count
        entry_count = struct.unpack(">I", data[idx : idx + 4])[0]
        idx += 4

        for _ in range(entry_count):
            # Skip entry name hash
            idx += 16

    log("Extracting encrypted keyring data...", 3)

    encrypted_data = data[idx:]

    return cipher, folder_count, encrypted_data


def decrypt_kwallet_data(cipher, encrypted_data: bytes, key: bytes):
    if cipher == CIPHER_BF_CBC:
        # Decrypt the data using BLOWFISH CBC
        iv = b"\x00" * 8
        decrypted_data = blowfish_cbc_decrypt(key, iv, encrypted_data)
    elif cipher == CIPHER_BF_ECB:
        decrypted_data = blowfish_ecb_decrypt(key, encrypted_data)
    elif cipher == CIPHER_GPG:
        raise NotImplementedError()
    else:
        raise NotImplementedError("Unexpected cipher found.")

    return decrypted_data


# Extract the passphrase from the decrypted KWallet data
def extract_passphrase(kwallet: bytes, folder_count: int):
    # HACK: Will use an unorthodox way to check if we decrypted the KWallet correctly

    # A KWallet with the required passphrase will include this byte sequence
    if CHROMIUM_BYTE_SEQ_3 not in kwallet:
        raise ValueError(
            "Decrypted KWallet does not contain the expected byte sequence. Either the KWallet is not decrypted correctly or it does not contain the required passphrase."
        )

    idx = 12
    passphrase = None

    for _ in range(folder_count):
        check_entries = False

        # Get the folder name length
        fn_len = struct.unpack(">I", kwallet[idx : idx + 4])[0]
        idx += 4
        folder_name = kwallet[idx : idx + fn_len].decode("utf-16-be")
        idx += fn_len
        if folder_name == "Chromium Keys":
            check_entries = True

        num_entries = struct.unpack(">I", kwallet[idx : idx + 4])[0]
        idx += 4
        for _ in range(num_entries):
            # Get the entry name length
            en_len = struct.unpack(">I", kwallet[idx : idx + 4])[0]
            idx += 4
            if check_entries:
                entry_name = kwallet[idx : idx + en_len].decode("utf-16-be")
            idx += en_len
            e_type = struct.unpack(">i", kwallet[idx : idx + 4])[0]
            idx += 4 + 4

            if e_type != 1:
                # Its not the entry type we are looking for, skip it entirely
                entry_val_len = struct.unpack(">I", kwallet[idx - 4 : idx])[0]
                idx += entry_val_len
            else:
                secret_len = struct.unpack(">I", kwallet[idx : idx + 4])[0]
                idx += 4 + secret_len

                if check_entries and entry_name == "Chromium Safe Storage":
                    # This is the entry we are looking for
                    passphrase = kwallet[idx - secret_len : idx].decode("utf-16-be").encode("utf-8")
                    break
    if passphrase is None:
        raise ValueError("The required passphrase was not found in the KWallet.")
    return passphrase


def kwallet_get_aux_key_passphrase(kwallet_path: str, salt: bytes, password: bytes) -> bytes:
    """
    Manually fetches the passphrase required to derive the auxiliary key for Signal from KWallet.
    """

    log("Fetching the passphrase from KWallet...", 1)
    cipher, folder_count, encrypted_kwallet_data = process_kwallet_file(pathlib.Path(kwallet_path))

    log("Deriving PBKDF2 key...", 2)
    kw_key = pbkdf2_derive_key(algorithm=SHA512(), password=password, salt=salt, iterations=50000, key_length=56)
    log(f"> KWallet Key: {bytes_to_hex(kw_key)}", 3)

    log("Decrypting the KWallet data...", 2)
    kwallet = decrypt_kwallet_data(cipher=cipher, encrypted_data=encrypted_kwallet_data, key=kw_key)

    log("Extracting the passphrase from the KWallet data...", 2)
    passphrase = extract_passphrase(kwallet, folder_count)
    log(f"> Passphrase: {repr(passphrase)}", 3)

    return passphrase


def kwallet_test_get_sqlcipher_key(kwallet_path: str, salt: bytes, password: bytes, encrypted_key: bytes):
    passphrase = kwallet_get_aux_key_passphrase(kwallet_path, salt, password)
    aux_key = linux_derive_aux_key(passphrase)

    # Decrypt the SQLCipher key using the auxiliary key
    decryption_key = linux_get_sqlcipher_key_from_aux(encrypted_key, aux_key).decode("utf-8")  # TODO: Error handling

    return decryption_key
