import struct
import pathlib
import os
import uuid
from modules.shared_utils import bytes_to_hex, log, MalformedKeyError
from modules.crypto import get_hash_algorithm, hash_sha1

####################### MANUAL MODE FUNCTIONS #######################


def process_dpapi_blob(data: bytes):
    try:
        log("Extracting data from DPAPI BLOB...", 2)
        master_key_guid = str(uuid.UUID(bytes_le=data[24:40]))
        log(f"> Master Key GUID: {master_key_guid}", 3)
        desc_len = struct.unpack("<I", data[44:48])[0]
        idx = 48 + desc_len + 8
        salt_len = struct.unpack("<I", data[idx : idx + 4])[0]
        idx += 4
        salt = data[idx : idx + salt_len]
        log(f"> BLOB Salt: {bytes_to_hex(salt)}", 3)
        idx += salt_len
        hmac_key_len = struct.unpack("<I", data[idx : idx + 4])[0]
        idx += 4 + hmac_key_len + 8
        hmac_key_len = struct.unpack("<I", data[idx : idx + 4])[0]
        idx += 4 + hmac_key_len
        data_len = struct.unpack("<I", data[idx : idx + 4])[0]
        idx += 4
        cipher_data = data[idx : idx + data_len]
        log(f"> Cipher Data: {bytes_to_hex(cipher_data)}", 3)
        return master_key_guid, salt, cipher_data
    except Exception as e:
        raise MalformedKeyError("Failed to extract information from the auxiliary key blob.") from e


def process_dpapi_master_key_file(master_key_path: pathlib.Path):
    if not master_key_path.is_file():
        raise FileNotFoundError(f"Master Key file '{master_key_path}' does not exist.")
    log("Reading from the master key file...", 3)
    with master_key_path.open("rb") as f:
        data = f.read()
    log("Processing the master key file...", 2)

    idx = 96
    master_key_len = struct.unpack("<Q", data[idx : idx + 8])[0]
    idx += 8 + 24 + 4
    salt = data[idx : idx + 16]
    log(f"> Master Key Salt: {bytes_to_hex(salt)}", 3)
    idx += 16
    rounds = struct.unpack("<I", data[idx : idx + 4])[0]
    log(f"> Rounds: {rounds}", 3)
    idx += 4
    hash_alg_id = struct.unpack("<I", data[idx : idx + 4])[0]
    log(f"> Algorithm Hash ID: {hash_alg_id}", 3)
    idx += 4 + 4
    encrypted_master_key = data[idx : idx + master_key_len - 32]
    log(f"> Encrypted Master Key: {bytes_to_hex(encrypted_master_key)}", 3)
    return salt, rounds, hash_alg_id, master_key_len, encrypted_master_key


def unprotect_manually(data: bytes, sid: str, password: str):
    try:
        log("[i] Unprotecting the auxiliary key manually...", 1)
        master_key_guid, blob_salt, cipher_data = process_dpapi_blob(data)
        log("Crafting the master key path...", 2)
        master_key_path = pathlib.Path(os.getenv("APPDATA")) / "Microsoft" / "Protect" / sid / master_key_guid
        log(f"> Master Key Path: {master_key_path}", 3)
        mk_salt, hash_rounds, hash_alg_id, mk_len, encrypted_master_key = process_dpapi_master_key_file(master_key_path)
        log("Deriving the master key's encription key...", 2)
        hash_alg = get_hash_algorithm(hash_alg_id)
        nt_hash = hash_sha1(password.encode("utf-16le"))
        log(f"> NT Hash: {bytes_to_hex(nt_hash)}", 3)
        # mk_encryption_key = pbkdf2_derive_key(hash_alg, nt_hash, mk_salt, hash_rounds, 32)
        # log(f"> Master Key Encryption Key: {bytes_to_hex(mk_encryption_key)}", 3)
        log("Decrypting the master key...", 2)

        # TODO: List requirements for manual acquisition of Aux Key?

        raise NotImplementedError("Manual mode is not implemented yet.")
    except Exception as e:
        raise MalformedKeyError("Failed to unprotect the auxiliary key manually.") from e
