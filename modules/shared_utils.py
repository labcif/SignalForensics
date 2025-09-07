import mimetypes
import struct
import pathlib

quiet = False
verbose = 0

files_hashes = set()


def log(message: str, level: int = 0):
    if not quiet and (verbose >= level):
        print(message)


def save_file_hash(file_path: pathlib.Path, category: str):
    from modules.crypto import hash_file

    file_hash = hash_file(file_path)
    files_hashes.add((category, bytes_to_hex(file_hash), str(file_path)))


def bytes_to_hex(data: bytes):
    return "".join(f"{b:02x}" for b in data)


def mime_to_extension(mime_type):
    """Converts a MIME type to a file extension."""
    extension = mimetypes.guess_extension(mime_type)
    return extension


# Skip the string length in a keyring or kwallet file
def skip_string(data, idx):
    # Skip the string length
    idk = idx + 4
    if data[idk - 4 : idk] != bytes.fromhex("FFFFFFFF"):
        str_len = struct.unpack(">I", data[idk - 4 : idk])[0]
        idk += str_len
    return idk


####################### EXCEPTIONS #######################


class MalformedKeyError(Exception):
    """Exception raised for a malformed key."""

    pass


class MalformedInputFileError(Exception):
    """Exception raised for a malformed input file."""

    pass
