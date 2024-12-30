quiet = False
verbose = 0


def log(message: str, level: int = 0):
    if not quiet and (verbose >= level):
        print(message)


def bytes_to_hex(data: bytes):
    return "".join(f"{b:02x}" for b in data)


####################### EXCEPTIONS #######################


class MalformedKeyError(Exception):
    """Exception raised for a malformed key."""

    pass
