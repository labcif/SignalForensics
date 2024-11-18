import argparse
import pathlib
import os
import json
import base64
import win32crypt

VERSION = "1.0"

AUX_KEY_PREFIX = "DPAPI"


# Parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser(
        prog="SignalDecryptor",
        description="Decrypts the forensic artifacts from Signal Desktop on Windows",
        usage="""%(prog)s [-m auto] -d <signal_dir> -o <output_dir> [OPTIONS]
        %(prog)s -m manual -d <signal_dir> -o <output_dir> -wS <SID> -wP <password> [OPTIONS]
        %(prog)s -m aux -d <signal_dir> -o <output_dir> [-kf <file> | -k <HEX>] [OPTIONS]
        %(prog)s -m key -d <signal_dir> -o <output_dir> [-kf <file> | -k <HEX>] [OPTIONS]
        """,
    )  # TODO: Better usage message
    # [-d <signal_dir> | (-c <file> -ls <file>)]

    # Informational arguments
    parser.add_argument(
        "-V",
        "--version",
        help="Print the version of the script",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    # Custom function to parse mode argument
    def parse_mode(value):
        aliases = {
            "auto": "auto",
            "manual": "manual",
            "aux": "aux",
            "key": "key",
            "a": "auto",
            "m": "manual",
            "ak": "aux",
            "dk": "key",
        }
        normalized_value = value.lower()
        if normalized_value not in aliases:
            raise argparse.ArgumentTypeError(f"Invalid mode '{value}'. Valid choices are: {', '.join(aliases.keys())}")
        return aliases[normalized_value]

    # Custom type function to convert HEX to bytes
    def hex_to_bytes(value):
        value = value.replace(" ", "").lower()
        try:
            return bytes.fromhex(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid HEX string: {value}")

    # Define mode argument
    parser.add_argument(
        "-m",
        "--mode",
        help=(
            "Mode of operation (choices: 'auto' for Windows Auto, 'manual' for Windows Manual, "
            "'aux' for Auxiliary Key Provided, 'key' for Decryption Key Provided). "
            "Short aliases: -mA (Auto), -mM (Manual), -mAK (Auxiliary Key), -mDK (Decryption Key)"
            "Default: auto"
        ),
        type=parse_mode,
        choices=["auto", "manual", "aux", "key"],
        metavar="{auto|manual|aux|key}",
        default="auto",
    )

    # IO arguments
    io_group = parser.add_argument_group(
        "Input/Output",
        "Arguments related to input/output paths. Output directory and either Signal's directory or configuration and local state files are required.",
    )
    io_group.add_argument(
        "-d", "--dir", help="Path to Signal's Roaming directory", type=pathlib.Path, metavar="<dir>", required=True
    )  # TODO: Change Roaming to other stuff
    io_group.add_argument(
        "-o",
        "--output",
        help="Path to the output directory",
        type=pathlib.Path,
        metavar="<dir>",
        required=True,
    )
    # io_group.add_argument(
    #    "-c", "--config", help="Path to the Signal's configuration file", type=pathlib.Path, metavar="<file>"
    # )
    # io_group.add_argument(
    #    "-ls", "--local-state", help="Path to the Signal's Local State file", type=pathlib.Path, metavar="<file>"
    # )

    # DPAPI related arguments
    manual_group = parser.add_argument_group("Windows Manual Mode", "Arguments required for manual mode.")
    manual_group.add_argument("-wS", "--windows-user-sid", help="Target windows user's SID", metavar="<SID>")
    manual_group.add_argument("-wP", "--windows-password", help="Target windows user's password", metavar="<password>")

    # Provided key related arguments
    key_group = parser.add_argument_group(
        "Key Provided Modes", "Arguments available for both Key Provided modes."
    ).add_mutually_exclusive_group()
    key_group.add_argument(
        "-kf",
        "--key-file",
        help="Path to the file containing the HEX encoded key as a string",
        type=pathlib.Path,
        metavar="<file>",
    )
    key_group.add_argument("-k", "--key", help="Key in HEX format", type=hex_to_bytes, metavar="<HEX>")

    # Operational arguments
    parser.add_argument("-sa", "--skip-attachments", help="Skip attachment decryption", action="store_true")

    # Verbosity arguments
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")
    verbosity_group.add_argument("-q", "--quiet", help="Enable quiet output", action="store_true")

    # Parse arguments
    return parser.parse_args()


# Validate arguments
def validate_args(args: argparse.Namespace):

    # Validate Signal directory
    if not args.dir.is_dir():
        raise FileNotFoundError(f"Signal directory '{args.dir}' does not exist or is not a directory.")
    else:
        args.config = args.dir / "config.json"
        args.local_state = args.dir / "Local State"

        # Check for Signal's configuration file
        if not args.config.is_file():
            raise FileNotFoundError(f"Signal's configuration file '{args.config}' does not exist or is not a file.")

        # Check for Signal's local state file
        if not args.local_state.is_file():
            raise FileNotFoundError(f"Signal's local state file '{args.local_state}' does not exist or is not a file.")

    # Validate output directory
    if not args.output.is_dir():
        try:
            os.makedirs(args.output)
        except OSError as e:
            raise FileNotFoundError(f"Output directory '{args.output}' does not exist and could not be created.") from e

    # Validate manual mode arguments
    if args.mode == "manual":
        if not args.windows_user_sid:
            raise ValueError("Windows User SID is required for manual mode.")
        if not args.windows_password:
            raise ValueError("Windows User Password is required for manual mode.")

    # Validate key provided mode arguments
    if args.mode in ["aux", "key"]:
        if args.key_file:
            if not args.key_file.is_file():
                raise FileNotFoundError(f"Key file '{args.key_file}' does not exist or is not a file.")
        elif not args.key:
            raise ValueError("A key is required for Key Provided modes.")


class MalformedInputFileError(Exception):
    """Exception raised for a malformed input file."""

    pass


class MalformedKeyError(Exception):
    """Exception raised for a malformed key."""

    pass


def unprotect_with_dpapi(data: bytes):
    try:
        _, decrypted_data = win32crypt.CryptUnprotectData(data)
        return decrypted_data
    except Exception as e:
        raise ValueError("Failed to unprotect the auxiliary key with DPAPI.") from e


def fetch_aux_key(args: argparse.Namespace):
    # If the user provided the auxiliary key, return it
    if args.mode == "aux":
        # If a key file is provided, read the key from the file
        if args.key_file:
            with args.key_file.open("r") as f:
                return bytes.fromhex(f.read().strip())
        return args.key
    else:
        with args.local_state.open("r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                raise MalformedInputFileError("The Local State file was malformed: Invalid JSON structure.")

            # Validate the presence of "os_crypt" and "encrypted_key"
            encrypted_key = data.get("os_crypt", {}).get("encrypted_key")
            if not encrypted_key:
                raise MalformedInputFileError(
                    "The Local State file was malformed: Missing the encrypted auxiliary key."
                )

            # Decode the base64 encoded key and remove the prefix
            try:
                encrypted_key = base64.b64decode(encrypted_key)[len(AUX_KEY_PREFIX) :]
            except ValueError:
                raise MalformedKeyError("The encrypted key is not a valid base64 string.")
            except IndexError:
                raise MalformedKeyError("The encrypted key is malformed.")

            if args.mode == "auto":
                return unprotect_with_dpapi(encrypted_key)
    return None


def bytes_to_hex(data: bytes):
    return "".join(f"{b:02x}" for b in data)


def main():
    args = parse_args()
    validate_args(args)

    # Setup logging
    quiet = args.quiet
    verbose = 1 if args.verbose else 0

    def log(message: str, level: int = 0):
        if not quiet and (verbose >= level):
            print(message)

    if args.mode != "key":
        aux_key = fetch_aux_key(args)
        if aux_key:
            print(bytes_to_hex(aux_key))
            return

    # ....


if __name__ == "__main__":
    main()
