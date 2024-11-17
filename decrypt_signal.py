import argparse
import pathlib

VERSION = "1.0"


# Parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser(
        prog="SignalDecryptor",
        description="Decrypts the forensic artifacts from Signal Desktop on Windows",
        usage="""%(prog)s [-m auto] -o <output_dir> [-d <signal_dir> | (-c <file> -ls <file>)] [OPTIONS]
        %(prog)s -m manual -o <output_dir> -wS <SID> -wP <password> [-d <signal_dir> | (-c <file> -ls <file>)] [OPTIONS]
        %(prog)s -m aux -o <output_dir> [-kf <file> | -k <HEX>] [-d <signal_dir> | (-c <file> -ls <file>)] [OPTIONS]
        %(prog)s -m key -o <output_dir> [-kf <file> | -k <HEX>] [-d <signal_dir> | (-c <file> -ls <file>)] [OPTIONS]
        """,
    )  # TODO: Better usage message

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
            "Mode of operation (choices: 'auto' for Auto, 'manual' for Manual, "
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
        "-o",
        "--output",
        help="Path to the output directory",
        type=pathlib.Path,
        metavar="<dir>",
        required=True,
    )
    io_group.add_argument(
        "-d", "--dir", help="Path to Signal's directory", type=pathlib.Path, metavar="<dir>"
    )  # TODO: Turn this into an optional argument
    io_group.add_argument(
        "-c", "--config", help="Path to the Signal's configuration file", type=pathlib.Path, metavar="<file>"
    )
    io_group.add_argument(
        "-ls", "--local-state", help="Path to the Signal's Local State file", type=pathlib.Path, metavar="<file>"
    )

    # DPAPI related arguments
    manual_group = parser.add_argument_group("Manual Mode", "Arguments required for manual mode.")
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
    verbosity_group.add_argument("-v", "--verbose", help="Enable verbose output", action="count", default=0)
    verbosity_group.add_argument("-q", "--quiet", help="Enable quiet output", action="store_true")

    # Parse arguments
    return parser.parse_args()


args = parse_args()
