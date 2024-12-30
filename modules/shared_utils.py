quiet = False
verbose = 0


def log(message: str, level: int = 0):
    if not quiet and (verbose >= level):
        print(message)
