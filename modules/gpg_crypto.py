GPG_BINARY = "gpg"


def decrypt_kwallet_gpg(data: bytes, key_asc: str, passphrase: str) -> bytes:
    try:
        import gnupg

        gpg = gnupg.GPG(gpgbinary=GPG_BINARY)

        import_result = gpg.import_keys(key_asc)
        if not import_result.count:
            raise RuntimeError("Failed to import the key")

        decrypted = gpg.decrypt(data, passphrase=passphrase)
    except Exception as e:
        raise RuntimeError(f"[!] GPG decryption failed: {e}")

    return decrypted.data
