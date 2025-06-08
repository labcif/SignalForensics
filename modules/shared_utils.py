import mimetypes

quiet = False
verbose = 0


def log(message: str, level: int = 0):
    if not quiet and (verbose >= level):
        print(message)


def bytes_to_hex(data: bytes):
    return "".join(f"{b:02x}" for b in data)


def mime_to_extension(mime_type):
    """Converts a MIME type to a file extension."""
    extension = mimetypes.guess_extension(mime_type)
    return extension


####################### EXCEPTIONS #######################


class MalformedKeyError(Exception):
    """Exception raised for a malformed key."""

    pass


class MalformedInputFileError(Exception):
    """Exception raised for a malformed input file."""

    pass
