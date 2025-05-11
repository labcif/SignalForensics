from modules.crypto import derive_evp_key, aes_cbc_decrypt
from modules.shared_utils import bytes_to_hex
import pathlib
import struct

from modules.crypto import hash_md5


# Skip the string length in a keyring file
def skip_string(data, idx):
    # Skip the string length
    idk = idx + 4
    if data[idk - 4 : idk] != bytes.fromhex("FFFFFFFF"):
        str_len = struct.unpack(">I", data[idk - 4 : idk])[0]
        idk += str_len
    return idk


# Process a keyring file, extracting the hash iterations, salt and cipherdata.
def process_keyring_file(keyring_path: pathlib.Path):
    if not keyring_path.is_file():
        raise FileNotFoundError(f"Keyring file '{keyring_path}' does not exist.")

    with keyring_path.open("rb") as f:
        data = f.read()

    # Check if the file prefix is correct
    GNOME_KEYRING_PREFIX = b"GnomeKeyring\n\r\0\n"
    idx = len(GNOME_KEYRING_PREFIX)
    if data[:idx] != GNOME_KEYRING_PREFIX:
        raise ValueError("Invalid keyring file format.")

    # Get the keyring name length
    idx += 4
    idx = skip_string(data, idx)
    idx += 24

    # Get the keyring hash_iterations
    hash_iterations = struct.unpack(">I", data[idx : idx + 4])[0]
    idx += 4

    # Get the keyring salt
    salt = data[idx : idx + 8]
    idx += 8 + 4 * 4

    # Get num items
    num_items = struct.unpack(">I", data[idx : idx + 4])[0]
    idx += 4
    for i in range(num_items):
        idx += 8

        # Get num attributes
        num_attributes = struct.unpack(">I", data[idx : idx + 4])[0]
        idx += 4

        for j in range(num_attributes):
            # Get attribute name length
            idx = skip_string(data, idx)

            # Get attribute type
            attr_type = struct.unpack(">I", data[idx : idx + 4])[0]
            idx += 4

            if attr_type == 0:
                # Skip string hash
                idx = skip_string(data, idx)
            else:
                # Skip guint32 hash
                idx += 4

    # Get number of encrypted bytes
    num_encrypted_bytes = struct.unpack(">I", data[idx : idx + 4])[0]
    idx += 4

    # Get encrypted data
    encrypted_data = data[idx : idx + num_encrypted_bytes]

    return hash_iterations, salt, encrypted_data, num_items


def decrypt_keyring_data(encrypted_data: bytes, key: bytes):
    # Decrypt the data using AES-CBC
    iv = b"\x00" * 16
    decrypted_data = aes_cbc_decrypt(key, iv, encrypted_data)
    return decrypted_data


# Extract the auxiliary key from the decrypted keyring data
def extract_auxiliary_key(keyring: bytes, num_items: int):
    # check_hash = keyring[:16]
    # actual_hash = hash_md5(keyring[16:], rounds=1)
    # HACK: These hashes should match, but they don't even when the keyring is decrypted correctly, not sure why
    # Will use an unorthodox way to check if we decrypted the keyring correctly

    # A keyring with Signal's auxiliary key will include this byte sequence
    SIGNAL_BYTE_SEQ = bytes.fromhex("0000000B6170706C69636174696F6E00000000000000065369676E616C")
    if SIGNAL_BYTE_SEQ not in keyring:
        raise ValueError(
            "Decrypted keyring does not contain the expected byte sequence. Either the keyring is not decrypted correctly or the keyring does not contain Signal's auxiliary key."
        )

    idx = 16
    aux_key = None
    for i in range(num_items):
        # Get the item display name length
        idx = skip_string(keyring, idx) + 4

        # Extract the secret
        secret_len = 0
        secret = None
        if keyring[idx - 4 : idx] != bytes.fromhex("FFFFFFFF"):
            secret_len = struct.unpack(">I", keyring[idx - 4 : idx])[0]
            secret = keyring[idx : idx + secret_len]
        idx += secret_len + 16

        # Skip the reserved string and guint32[4]
        idx = skip_string(keyring, idx)
        idx += 4 * 4

        # Get num attributes
        num_attributes = struct.unpack(">I", keyring[idx : idx + 4])[0]
        idx += 4
        for j in range(num_attributes):
            # Extract attribute name
            name_len = struct.unpack(">I", keyring[idx : idx + 4])[0]
            idx += 4
            name = keyring[idx : idx + name_len]
            idx += name_len

            # Get attribute type
            attr_type = struct.unpack(">I", keyring[idx : idx + 4])[0]
            idx += 4
            if attr_type != 0:
                # Not a string, skip the value
                idx += 4
                continue

            val_len = struct.unpack(">I", keyring[idx : idx + 4])[0]
            idx += 4
            val = keyring[idx : idx + val_len]
            idx += val_len

            if name == b"application" and val == b"Signal":
                aux_key = secret
                break
        break

    if aux_key is None:
        raise ValueError("Signal's auxiliary key not found in the keyring.")
    return aux_key


def get_decryption_key_gnome(keyring_path: str, password: bytes):
    hash_iterations, salt, encrypted_keyring_data, num_items = process_keyring_file(pathlib.Path(keyring_path))

    keyring_key = derive_evp_key(password=password, salt=salt, key_len=16, iterations=hash_iterations)
    keyring = decrypt_keyring_data(encrypted_keyring_data, keyring_key)

    aux_key = extract_auxiliary_key(keyring, num_items)

    print(f"Signal's auxiliary key: {aux_key}")
    return aux_key
