import argparse
import pathlib
import os
import json
import base64
import random
import string
import sys
import csv
from datetime import datetime
import pytz
from collections import defaultdict

import sqlcipher3

from modules import shared_utils as su
from modules.shared_utils import bytes_to_hex, log, MalformedKeyError, MalformedInputFileError, mime_to_extension
from modules.crypto import aes_cbc_decrypt, hash_sha256
from modules.htmlreport import generate_html_report
from modules.gnome import gnome_derive_aux_key, gnome_get_aux_key_passphrase, gnome_get_sqlcipher_key_from_aux
from modules.windows import win_fetch_encrypted_aux_key, unprotect_manually, win_get_sqlcipher_key_from_aux

####################### CONSTANTS #######################
VERSION = "2.1.1"

EMPTY_IV = "AAAAAAAAAAAAAAAAAAAAAA=="  # 16 bytes of 0x00

ATTACHMENT_FOLDER = pathlib.Path("attachments.noindex")
AVATARS_FOLDER = pathlib.Path("avatars.noindex")
DRAFTS_FOLDER = pathlib.Path("drafts.noindex")
DOWNLOADS_FOLDER = pathlib.Path("downloads.noindex")

####################### I/O ARGS #######################


# Parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser(
        prog="SignalDecryptor",
        description="Decrypts the forensic artifacts from Signal Desktop on Windows",
        usage="""%(prog)s [-m live] [-e <environment>] -d <signal_dir> [-o <output_dir>] [OPTIONS]
        %(prog)s -m aux [-e <environment>] -d <signal_dir> [-o <output_dir>] [-kf <file> | -k <HEX>] [OPTIONS]
        %(prog)s -m key [-e <environment>] -d <signal_dir> -o <output_dir> [-kf <file> | -k <HEX>] [OPTIONS]
        %(prog)s -m forensic [-e <environment>] -d <signal_dir> [-o <output_dir>] -p <password> [OPTIONS]
        """,
    )
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
            "live": "live",
            "forensic": "forensic",
            "aux": "aux",
            "key": "key",
            "l": "live",
            "f": "forensic",
            "a": "aux",
            "k": "key",
        }
        normalized_value = value.lower()
        if normalized_value not in aliases:
            raise argparse.ArgumentTypeError(f"Invalid mode '{value}'. Valid choices are: {', '.join(aliases.keys())}")
        return aliases[normalized_value]

    # Custom function to parse env argument
    def parse_env(value):
        aliases = {
            "windows": "windows",
            "gnome": "gnome",
            "win": "windows",
            "w": "windows",
            "g": "gnome",
        }
        normalized_value = value.lower()
        if normalized_value not in aliases:
            raise argparse.ArgumentTypeError(
                f"Invalid environment '{value}'. Valid choices are: {', '.join(aliases.keys())}"
            )
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
            "Mode of execution (choices: 'live' for Live, 'aux' for Auxiliary Key Provided, "
            "'key' for SQLCipher Key Provided), 'forensic' for Forensic. "
            "Short aliases: -mL (Live), -mA (Auxiliary Key), -mK (SQLCipher Key), -mF (Forensic)"
            "Default: live"
        ),
        type=parse_mode,
        choices=["live", "aux", "key", "forensic"],
        metavar="{live|aux|key|forensic}",
        default="live",
    )

    # Define environment argument
    parser.add_argument(
        "-e",
        "--env",
        help="Environment from which the Signal data was extracted (currently only 'windows' and 'gnome' are supported)."
        "Short aliases: -eW (Windows), -eG (Gnome)."
        "Default: windows",
        type=parse_env,
        choices=["windows", "gnome"],
        metavar="{windows|gnome}",
        default="windows",
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
    )
    # io_group.add_argument(
    #    "-c", "--config", help="Path to the Signal's configuration file", type=pathlib.Path, metavar="<file>"
    # )
    # io_group.add_argument(
    #    "-ls", "--local-state", help="Path to the Signal's Local State file", type=pathlib.Path, metavar="<file>"
    # )

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

    # Forensic Mode related arguments
    forensic_group = parser.add_argument_group("Forensic Mode", "Arguments required for forensic mode.")
    forensic_group.add_argument(
        "-p",
        "--password",
        help="Gnome Keyring's master password (by default, it is the same as the user account's password)",
        type=str,
        metavar="<password>",
    )
    forensic_group.add_argument(
        "-pb",
        "--password-bytes",
        help="Gnome Keyring's master password in HEX format",
        type=hex_to_bytes,
        metavar="<bytes>",
    )
    forensic_group.add_argument(
        "-pbf",
        "--password-bytes-file",
        help="Path to the file containing the Gnome Keyring's master password in HEX format",
        type=pathlib.Path,
        metavar="<file>",
    )
    forensic_group.add_argument(
        "-gkf",
        "--gnome-keyring-file",
        help="Path to the user's Gnome Keyring file",
        type=pathlib.Path,
        metavar="<file>",
    )
    # manual_group.add_argument("-wS", "--windows-sid", help="Target windows user's SID", metavar="<SID>")
    # manual_group.add_argument("-wP", "--windows-password", help="Target windows user's password", metavar="<password>")

    # Operational/Options arguments
    parser.add_argument(
        "-nd", "--no-decryption", help="No decription, just print the SQLCipher key", action="store_true"
    )
    parser.add_argument(
        "-sD", "--skip-database", help="Skip exporting a decrypted copy of the database", action="store_true"
    )
    parser.add_argument("-sA", "--skip-attachments", help="Skip attachment decryption", action="store_true")
    parser.add_argument(
        "-sR", "--skip-reports", help="Skip the generation of CSV and HTML reports", action="store_true"
    )

    # Validate the provided timezone.
    def validate_timezone(value):
        if value not in pytz.all_timezones:
            raise argparse.ArgumentTypeError(
                f"Invalid timezone: {value}. Please provide a valid timezone (e.g., UTC, GMT, PST, Europe/Lisbon)."
            )
        return value

    parser.add_argument(
        "-t",
        "--convert-timestamps",
        nargs="?",
        const="UTC",
        default=None,
        type=validate_timezone,
        metavar="[timezone]",  # REVIEW: [] ? or <>
        help="Convert timestamps to human-readable format. Provide a timezone (e.g., UTC, GMT, PST). Defaults to UTC when no timezone is provided.",
    )

    parser.add_argument(
        "-mc",
        "--merge-conversations",
        help="Merge message related reports into single CSV files instead of separating them by conversation",
        action="store_true",
    )

    # parser.add_argument(
    #    "-iM", "--include-metadata", help="Print user metadata from Signal database", action="store_true"
    # )

    # Verbosity arguments
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("-v", "--verbose", help="Enable verbose output", action="count", default=0)
    verbosity_group.add_argument("-q", "--quiet", help="Enable quiet output", action="store_true")

    # Parse arguments
    return parser.parse_args()


# Validate arguments
def validate_args(args: argparse.Namespace):

    # Validate OS-specific modes
    if args.mode == "live":
        if not sys.platform.startswith("win") and not sys.platform.startswith("linux"):
            raise OSError("Live mode is currently only available on Windows and Linux Gnome.")
    elif args.mode == "forensic":
        if args.env != "gnome":
            raise OSError("Forensic mode is only supported for artifacts originating from a Linux Gnome environment.")

    # Validate Signal directory
    if not args.dir.is_dir():
        raise FileNotFoundError(f"Signal directory '{args.dir}' does not exist or is not a directory.")
    else:
        args.config = args.dir / "config.json"
        args.local_state = args.dir / "Local State"

        # Check for Signal's configuration file
        if not args.config.is_file():
            raise FileNotFoundError(f"Signal's configuration file '{args.config}' does not exist or is not a file.")

        if args.env == "windows":
            # Check for Signal's local state file
            if not args.local_state.is_file():
                raise FileNotFoundError(
                    f"Signal's local state file '{args.local_state}' does not exist or is not a file."
                )

    # Validate output directory
    if not args.output:
        if not args.no_decryption:
            log("[!] No output directory provided, assuming no decryption is required")
        args.no_decryption = True
    elif not args.output.is_dir():
        try:
            os.makedirs(args.output)
        except OSError as e:
            raise FileNotFoundError(f"Output directory '{args.output}' does not exist and could not be created.") from e

    # Validate manual mode arguments
    if args.mode == "forensic":
        # if not args.windows_sid:
        #    raise ValueError("Windows User SID is required for manual mode.")
        # if not args.windows_password:
        #    raise ValueError("Windows User Password is required for manual mode.")
        if args.password_bytes_file:
            if not args.password_bytes_file.is_file():
                raise FileNotFoundError(
                    f"Password bytes file '{args.password_bytes_file}' does not exist or is not a file."
                )
        elif not args.password and not args.password_bytes:
            raise ValueError("Gnome Keyring's master password is required for forensic mode.")

        if not args.gnome_keyring_file:
            raise ValueError("Gnome Keyring file is required for forensic mode.")

    # Validate key provided mode arguments
    if args.mode in ["aux", "key"]:
        if args.key_file:
            if not args.key_file.is_file():
                raise FileNotFoundError(f"Key file '{args.key_file}' does not exist or is not a file.")
        elif not args.key:
            raise ValueError("A key is required for Key Provided modes.")

    # If mode is Key Provided and skip decryption is enabled, raise an error
    if args.mode == "key" and args.skip_decryption:
        raise ValueError("Decryption cannot be skipped when providing the decryption key.")


####################### KEY FETCHING #######################


def fetch_hex_or_file_content_from_args(args_file, args_key, content="key"):
    """
    Fetches content from either a file or a hex string provided in the arguments.
    If a file is provided, it reads the content of the file and returns it as bytes.
    If a hex string is provided, it converts it to bytes and returns it.
    """
    # If a file is provided, read contents from the file
    if args_file:
        log(f"Reading the {content} from the file...", 2)
        with args_file.open("r") as f:
            return bytes.fromhex(f.read().strip())
    elif args_key:
        return args_key
    else:
        raise ValueError(f"No {content} provided. Please provide either a {content} file or a hex string.")


def fetch_key_from_args(args: argparse.Namespace):
    return fetch_hex_or_file_content_from_args(args.key_file, args.key, content="key")


def fetch_password_from_args(args: argparse.Namespace):
    if args.password_bytes_file or args.password_bytes:
        return fetch_hex_or_file_content_from_args(args.password_bytes_file, args.password_bytes, content="password")
    else:
        if not args.password:
            raise ValueError("No password provided. Please provide either a password or a password bytes file.")
        return args.password.encode("utf-8")


def fetch_aux_key(args: argparse.Namespace):
    # If the user provided the auxiliary key, return it
    if args.mode == "aux":
        return fetch_key_from_args(args)
    else:
        if args.env == "gnome":
            if args.mode == "live":
                from modules import gnome_live as gnome_live

                gnome_passphrase = gnome_live.gnome_get_aux_key_passphrase_live()
            elif args.mode == "forensic":
                gnome_password = fetch_password_from_args(args)
                gnome_passphrase = gnome_get_aux_key_passphrase(args.gnome_keyring_file, gnome_password)
            else:
                raise ValueError("An invalid mode for the Gnome environment was chosen!")
            return gnome_derive_aux_key(gnome_passphrase)
        else:
            encrypted_aux_key = win_fetch_encrypted_aux_key(args.local_state)
            if args.mode == "live":
                try:
                    from modules import windows_live as win_live
                except ImportError as e:
                    raise ImportError("Windows-specific module could not be imported:", e)
                return win_live.unprotect_with_dpapi(encrypted_aux_key)
            elif args.mode == "forensic":
                return unprotect_manually(encrypted_aux_key, args.windows_sid, args.windows_password)
    return None


def fetch_decryption_key(args: argparse.Namespace, aux_key: bytes):
    with args.config.open("r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            raise MalformedInputFileError("The Configuration file was malformed: Invalid JSON structure.")

        # Validate the presence of "encryptedKey"
        encrypted_key = data.get("encryptedKey")
        if not encrypted_key:
            raise MalformedInputFileError("The Configuration file was malformed: Missing the encrypted decryption key.")

        # Import the hex string into bytes
        try:
            key = bytes.fromhex(encrypted_key)
        except ValueError:
            raise MalformedKeyError("The encrypted decryption key is not a valid HEX string.")

        log("Processing the encrypted decryption key...", 2)

        if args.env == "gnome":
            decrypted_key = gnome_get_sqlcipher_key_from_aux(encrypted_key=key, aux_key=aux_key)
        else:
            decrypted_key = win_get_sqlcipher_key_from_aux(encrypted_key=key, aux_key=aux_key)

        log("> repr(SQLCipher Key): " + repr(decrypted_key.decode("utf-8")), 3)

        return bytes.fromhex(decrypted_key.decode("utf-8"))


####################### SQLCIPHER & DATABASE #######################


def open_sqlcipher_db(args: argparse.Namespace, key: bytes):
    db_path = args.dir / "sql" / "db.sqlite"
    cipher_key = bytes_to_hex(key)

    if not db_path.is_file():
        raise FileNotFoundError(f"Encrypted database '{db_path}' does not exist or is not a file.")

    # Connect to the database
    conn = sqlcipher3.connect(db_path)
    cursor = conn.cursor()

    # Decrypt the database
    statement = f"PRAGMA key = \"x'{cipher_key}'\""
    log(f"Executing: {statement}", 3)
    cursor.execute(statement)

    # Test if the decryption key is correct
    try:
        log("Trying SQLCipher key...", 2)
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
    except sqlcipher3.DatabaseError:
        raise sqlcipher3.DatabaseError("Failed to open the database.")

    # Export a decrypted copy of the database
    if not args.skip_database:
        unencrypted_db_path = args.output / "db.sqlite"
        if unencrypted_db_path.is_file():
            log("[!] The output directory already contains an SQLite DB, skipping export")
        else:
            udb_name = generate_db_name()
            cursor.execute(f"ATTACH DATABASE '{unencrypted_db_path}' AS {udb_name} KEY '';")
            cursor.execute(f"SELECT sqlcipher_export('{udb_name}');")
            cursor.execute(f"DETACH DATABASE {udb_name};")
            log(f"[i] Exported the unencryted database")

    return conn, cursor


def select_sql(cursor, statement, name=None):
    if name is not None:
        log(f"Fetching all {name}...", 2)
    try:
        cursor.execute(statement)
        arr = cursor.fetchall()
        if name is not None:
            log(f"Found {len(arr)} {name}", 1)
        return arr
    except sqlcipher3.DatabaseError as e:
        raise sqlcipher3.DatabaseError("Failed to execute SQL SELECT (", statement, ")") from e


def fetch_batches_select(cursor, statement, batch_size=10000):
    offset = 0
    while True:
        query = f"{statement} LIMIT {batch_size} OFFSET {offset}"
        cursor.execute(query)
        rows = cursor.fetchall()
        yield rows
        offset += batch_size

        # If the number of rows fetched is less than the batch size, stop fetching
        if len(rows) < batch_size:
            break


def handle_avatar(convJson, convType):
    """Yields the avatars in a conversation JSON."""
    keyName = "avatar" if convType == "group" else "profileAvatar"
    theAvatar = convJson.get(keyName, None)
    theAvatars = convJson.get("avatars", [])
    if theAvatar is not None:
        theAvatars.insert(0, theAvatar)
    for avatar in theAvatars:
        if avatar.get("localKey", None) is not None:
            avatar["iv"] = EMPTY_IV
            imgPath = avatar.get("imagePath", None)
            avatar["path_pref"] = AVATARS_FOLDER if imgPath else ATTACHMENT_FOLDER
            if imgPath is not None:
                avatar["path"] = imgPath
            yield avatar
    return


def process_attachment(args: argparse.Namespace, attachments_dir, attachment, statuses):
    if attachment.get("contentType", "") == "text/x-signal-story":
        return

    if "path" in attachment:
        subpath = attachment["path"]
    elif "downloadPath" in attachment:
        subpath = attachment["downloadPath"]
        statuses["error"] += 1
        log(
            f"[!] Skipping attachment with downloadPath: {DOWNLOADS_FOLDER}/{subpath}. Signal Desktop currently cannot manually decrypt this attachment.",
            2,
        )
        return
    else:
        statuses["error"] += 1
        fnForError = attachment.get("fileName", "unknown")
        log(f"[!] Could not find a path for an attachment with file name {fnForError}", 3)
        return

    try:
        # Fetch attachment crypto data
        key = base64.b64decode(attachment["localKey"])[:32]

        if "iv" not in attachment:
            # If the IV is not present in the attachment, use the empty IV
            attachment["iv"] = EMPTY_IV

        nonce = base64.b64decode(attachment["iv"])
        size = int(attachment["size"])

        # Encrypted attachment path
        folder = (
            (ATTACHMENT_FOLDER if "path" in attachment else DOWNLOADS_FOLDER)
            if "path_pref" not in attachment
            else attachment["path_pref"]
        )
        enc_attachment_path = args.dir / folder / subpath

        # Check if the encrypted attachment is present on the expected path
        if not enc_attachment_path.is_file():
            log(f"[!] Attachment {subpath} not found", 2)
            statuses["error"] += 1
            return

        # Fetch attachment cipherdata
        with enc_attachment_path.open("rb") as f:
            enc_attachment_data = f.read()

        # Decrypt the attachment
        attachment_data = aes_cbc_decrypt(key, nonce, enc_attachment_data)
        attachment_data = attachment_data[16 : 16 + size]  # Dismiss the first 16 bytes and the padding
        if bytes.fromhex(attachment["plaintextHash"]) != hash_sha256(attachment_data):
            log(f"[!] Attachment {subpath} failed integrity check", 2)
            statuses["integrity_error"] += 1

        # Save the attachment to a file
        filePath = subpath
        if "contentType" in attachment:
            filePath += f"{mime_to_extension(attachment['contentType'])}"

        # Ensure the parent directory exists
        attachment_path = attachments_dir / folder / filePath
        attachment_path.parent.mkdir(parents=True, exist_ok=True)
        with attachment_path.open("wb") as f:
            f.write(attachment_data)

        statuses["exported"] += 1
    except Exception as e:
        statuses["error"] += 1
        log(f"[!] Failed to export attachment {subpath}: {e}", 3)


def export_attachments(cursor, args: argparse.Namespace):
    """Export Signal attachments from the database."""

    attachments_dir = args.output

    statuses = {
        "error": 0,
        "exported": 0,
        "integrity_error": 0,
    }

    log("[i] Processing metadata and decrypting attachments...", 2)

    # Fetch and process message attachments
    for msg_batch in fetch_batches_select(
        cursor,
        "SELECT json from messages WHERE hasFileAttachments = TRUE OR hasAttachments = TRUE OR json LIKE '%\"preview\":[{%'",
        500,
    ):
        it_attachments = []

        for entry in msg_batch:
            # Parse the message metadata
            msgJson = json.loads(entry[0])
            attachments = msgJson.get("attachments", [])

            # Preview of embed urls
            if "preview" in msgJson and "image" in msgJson["preview"]:
                attachments.append(msgJson["preview"]["image"])

            it_attachments.extend(attachments)

        for attachment in it_attachments:
            process_attachment(args, attachments_dir, attachment, statuses)

        del it_attachments

    # Fetch conversation avatars and draft attachments
    conversations = select_sql(
        cursor,
        "SELECT json, type FROM conversations;",
        "conversations",
    )

    if len(conversations) == 0:
        log("[i] No conversations were found in the database")
    else:
        withAvatar = 0
        draftAttachments = 0
        it_attachments = []
        for conv in conversations:
            convJsonStr, convType = conv
            convJson = json.loads(convJsonStr)
            for avatar in handle_avatar(convJson, convType):
                avatar["contentType"] = "image/jpeg"
                it_attachments.append(avatar)
                withAvatar += 1
            for atch in convJson.get("draftAttachments", []):
                atch["iv"] = EMPTY_IV
                atch["path_pref"] = DRAFTS_FOLDER
                it_attachments.append(atch)
                draftAttachments += 1

        del conversations

        log(f"[i] Found {withAvatar} conversation avatars", 2)
        log(f"[i] Found {draftAttachments} draft attachments", 2)

        for attachment in it_attachments:
            process_attachment(args, attachments_dir, attachment, statuses)

    log(f"[i] Exported {statuses['exported']} attachments")
    if statuses["integrity_error"] > 0:
        log(
            f"[!] {statuses['integrity_error']} attachments failed integrity check (enable verbose mode 3 for more details)"
        )
    if statuses["error"] > 0:
        log(f"[!] Failed to export {statuses['error']} attachments (enable verbose mode 3 for more details)")


####################### CSV/HTML REPORTS #######################


def write_csv_file(path, headers, rows):
    """Writes a CSV file with the provided headers and rows."""
    if len(rows) == 0:
        return True
    try:
        fileExists = path.is_file()
        with open(path, "a", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile, delimiter=",")
            if not fileExists:
                csvfile.write("SEP=,\n")
                writer.writerow(headers)
            writer.writerows(rows)
    except Exception as e:
        log(f"[!] Failed to write CSV file: {e}")
        return False
    return True


def process_database_and_write_reports(cursor, args: argparse.Namespace):
    """Write reports from the artifacts found in the database"""

    reports_folder = args.output / "reports"
    reports_folder.mkdir(parents=True, exist_ok=True)

    log("[i] Processing the database...", 1)

    # Fetch the user's service ID
    user_uuid = None
    try:
        cursor.execute("SELECT json FROM items WHERE id = 'uuid_id';")
        row = cursor.fetchone()
        if row is None:
            log(f"[i] User's Service ID not found in items table", 1)
        user_uuid = json.loads(row[0]).get("value", None)
        if user_uuid is not None:
            user_uuid = user_uuid.split(".")[0]
    except sqlcipher3.DatabaseError as e:
        raise sqlcipher3.DatabaseError("Failed to retrieve items from database") from e

    # Fetch conversations
    conversations = select_sql(
        cursor,
        "SELECT id, json, type, active_at, serviceId, profileFullName, e164 FROM conversations;",
        "conversations",
    )

    if len(conversations) == 0:
        log("[i] No conversations were found in the database")
        return

    # Timestamp managing function
    def tts(timestamp, ms=True):
        if timestamp is None:
            return None
        if timestamp == 9007199254740991:
            return None
        return localize_timestamp(timestamp, args, ms)

    # Create CSV headers and row arrays
    CONVERSATIONS_HEADERS = [
        "ID",
        "Type",
        "Name",
        "Last Active At",
        "Unread Messages",
        "Total Message Count",
        "Sent Message Count",
        "Last Message Timestamp",
        "Last Message Author",
        "Last Message",
        "Last Message Deleted?",
        "Draft Timestamp",
        "Draft Message",
        "Draft Attachments",
        "Expire Timer (seconds)",
        "Is Archived?",
        "Avatar Path",
        "Added To Group By (ID)",
        "Added To Group By (Name)",
        "Group Description",
    ]
    CONTACTS_HEADERS = ["Conversation ID", "Service ID", "Name", "E164", "Username", "Profile Name", "Nickname", "Note"]
    GROUPS_MEMBERS_HEADERS = [
        "Conversation ID",
        "Group Name",
        "Group ID",
        "Type",
        "Member Service ID",
        "Member Name",
        "Role",
    ]
    conv_rows = []
    contacts_rows = []
    group_members_rows = []

    service2name = {}  # Dictionary of service ID to contact name
    group2name = {}  # Dictionary of group ID to group name
    conv2service = {}  # Dictionary of conversation ID to service ID
    conv2group = {}  # Dictionary of conversation ID to group ID
    convId2conv = {}  # Dictionary of conversation ID to name and type

    # Auxiliary functions
    def print_mentions_in_message(text, bodyRanges):
        """Prints mentions in the message."""
        if bodyRanges is None or text is None or type(bodyRanges) is not list:
            return text

        # Only include mentions, remove other bodyRanges
        bodyRanges = list(filter(lambda x: "mentionAci" in x, bodyRanges))

        if len(bodyRanges) == 0:
            return text

        newText = ""
        j = 0
        for i in range(len(bodyRanges)):
            mention = bodyRanges[i]
            if "mentionAci" not in mention:
                continue
            # Text before the mentio
            newText += text[j : mention["start"]]
            j += mention["start"] + mention["length"]  # Skip the mention's representation
            newText += "@" + mention.get("replacementText", service2name.get(mention["mentionAci"], "unknown"))
        return newText

    def process_message_bodyranges(
        msgJson,
        body=None,
        keyBodyRanges="bodyRanges",
        keyBody="body",
    ):
        """Process a message's body ranges."""
        msgBodyRanges = msgJson.get(keyBodyRanges, [])
        msgBody = body if body != None else msgJson.get(keyBody, None)
        if len(msgBodyRanges) > 0:
            msgBody = print_mentions_in_message(msgBody, msgBodyRanges)
        return msgBody

    def process_last_message(convJson):
        """Process the last message in a conversation."""
        last_message = print_mentions_in_message(
            convJson.get("lastMessage", None), convJson.get("lastMessageBodyRanges", None)
        )
        prefix = convJson.get("lastMessagePrefix", "")
        if prefix:
            last_message = f"{prefix} {last_message}"
        return last_message

    def process_group_members(convId, convJson):
        """Process group members and add to group_members_rows."""
        MEMBER_KEYS = {
            "membersV2": "Member",
            "pendingMembersV2": "Pending Member",
            "pendingAdminApprovalV2": "Pending Admin Approval",
            "bannedMembersV2": "Banned Member",
        }
        for mbrKey, memberType in MEMBER_KEYS.items():
            if mbrKey not in convJson:
                continue
            for member in convJson[mbrKey]:
                mbrServiceId = member.get("aci", member.get("serviceId", None))
                role = "Administrator" if member.get("role", None) == 2 else None
                group_members_rows.append(
                    [
                        convId,
                        convJson.get("name", ""),
                        convJson.get("groupId", None),
                        memberType,
                        mbrServiceId,
                        service2name.get(mbrServiceId, None),
                        role,
                    ]
                )

    def details_to_text(details):
        """Converts group change details to a readable string."""
        if details is None or "type" not in details:
            return None
        dType = details["type"]
        dRemoved = details.get("removed", None)

        dNewPriv = details.get("newPrivilege", None)
        newPrivSuffix = " to Admin only" if dNewPriv == 3 else " to All members"

        def get_mbr_suffix():
            mbrServiceId = details.get("aci", None)
            mbrName = service2name.get(mbrServiceId, "")
            return f"{mbrName} (Service ID: {mbrServiceId})"

        if dType == "create":
            return "Group created"
        elif dType == "title":
            return f"Group title changed to '{details.get('newTitle', '')}'"
        elif dType == "description":
            if not dRemoved:
                return f"Group description changed to '{details.get('description', '')}'"
            return "Group description removed"
        elif dType == "group-link-add":
            dPriv = details.get("privilege", None)
            if dPriv != 1 and dPriv != 3:
                return "Group link enabled"
            # 1 = without admin approval, 3 = with admin approval
            return f"Group link enabled {'without' if dPriv == 1 else 'with'} admin approval"
        elif dType == "group-link-reset":
            return "Group link reset"
        elif dType == "group-link-remove":
            return "Group link disabled"
        elif dType == "access-invite-link":
            # 3 = enabled, 1 = disabled
            return f"Admin approval {'enabled' if dNewPriv == 3 else 'disabled'} for group join link"
        elif dType == "access-members":
            return f"Permission to add members changed{newPrivSuffix}"
        elif dType == "access-attributes":
            return f"Permission to modify group information changed{newPrivSuffix}"
        elif dType == "announcements-only":
            if details.get("announcementsOnly", False):
                return "Group set to announcements only (only admins can send messages)"
            return "Group set to allow all members to send messages"
        elif dType == "avatar":
            if dRemoved:
                return "Group avatar removed"
            return "Group avatar changed"
        elif dType == "member-add":
            return f"Member added: {get_mbr_suffix()}"
        elif dType == "member-remove":
            return f"Member removed: {get_mbr_suffix()}"
        elif dType == "member-privilege":
            return f"Member role updated to {'Admin' if dNewPriv == 2 else 'Member'} for {get_mbr_suffix()}"

        return 'Uknown group change check "Details in JSON" for more information'

    myServiceId = None

    # Populate the service2name dictionary
    for conv in conversations:
        (convId, convJsonStr, convType, convActiveAt, serviceId, profileFullName, e164) = conv[:7]
        convJson = json.loads(convJsonStr)
        theName = convJson.get("name", "")
        if convType == "private":
            if theName == "":
                # If there is no "contact name" in the conversation JSON, use the profileFullName or e164
                theName = profileFullName if profileFullName is not None else e164
            service2name[serviceId] = theName
            conv2service[convId] = serviceId
            if "avatars" in convJson:
                myServiceId = serviceId
        elif convType == "group":
            groupId = convJson.get("groupId", None)
            group2name[groupId] = theName
            conv2group[convId] = groupId
        convId2conv[convId] = {"name": theName, "type": convType}

    # Process conversations table data
    for conv in conversations:
        (convId, convJsonStr, convType, convActiveAt, serviceId, profileFullName, e164) = conv[:7]
        convJson = json.loads(convJsonStr)

        avatarPathParts = [
            str(avatar["path_pref"] / avatar["path"])
            for avatar in handle_avatar(convJson, convType)
            if "path" in avatar
        ]
        if len(avatarPathParts) > 1:
            avatarPathParts[0] += " (CURRENT)"

        avatarPath = "\n".join(filter(None, avatarPathParts)) if len(avatarPathParts) > 0 else None

        convLastMsg = process_last_message(convJson)
        convDraftTimestamp = tts(convJson.get("draftTimestamp", None))
        convDraft = print_mentions_in_message(convJson.get("draft", None), convJson.get("draftBodyRanges", None))
        convDraftAttachments = convJson.get("draftAttachments", [])
        convDraftAttachments = [entry["path"] for entry in convDraftAttachments if "path" in entry]
        convDraftAttachmentsStr = (
            "\n".join(filter(None, convDraftAttachments)) if len(convDraftAttachments) > 0 else None
        )
        if convType == "private":
            cNote = convJson.get("note", None)
            cNickname = convJson.get("nicknameGivenName", "") + " " + convJson.get("nicknameFamilyName", "")
            cNickname = cNickname.strip()
            contacts_rows.append(
                [
                    convId,
                    serviceId,
                    convJson.get("name", ""),
                    e164,
                    convJson.get("username", ""),
                    profileFullName,
                    None if cNickname == "" else cNickname,
                    cNote,
                ]
            )
        elif convType == "group":
            process_group_members(convId, convJson)

        added_by = convJson.get("addedBy", None)

        # Append the conversation data to the CSV rows
        conv_rows.append(
            [
                convId,
                convType,
                convJson.get("name", ""),
                tts(convActiveAt),
                convJson.get("unreadCount", 0),
                convJson.get("messageCount", 0),
                convJson.get("sentMessageCount", 0),
                tts(convJson.get("lastMessageTimestamp", None)),
                convJson.get("lastMessageAuthor", None),
                convLastMsg,
                convJson.get("lastMessageDeletedForEveryone", None),
                convDraftTimestamp,
                convDraft,
                convDraftAttachmentsStr,
                convJson.get("expireTimer", None),  # REVIEW: Keep in seconds?
                convJson.get("isArchived", False),
                avatarPath,
                added_by,
                service2name.get(added_by, None),
                convJson.get("description", ""),
            ]
        )

    # Write the csv files
    if not write_csv_file(reports_folder / "conversations.csv", CONVERSATIONS_HEADERS, conv_rows):
        log("[!] Failed to write the conversations CSV file")
    if not write_csv_file(reports_folder / "contacts.csv", CONTACTS_HEADERS, contacts_rows):
        log("[!] Failed to write the contacts CSV file")
    if not write_csv_file(reports_folder / "groups_members.csv", GROUPS_MEMBERS_HEADERS, group_members_rows):
        log("[!] Failed to write the groups members CSV file")

    # Free memory
    conv_rows.clear()
    contacts_rows.clear()
    group_members_rows.clear()
    del conv_rows
    del contacts_rows
    del group_members_rows

    MESSAGES_HEADERS = [
        "Message ID",
        "Type",
        "Conversation ID",
        "Conversation Type",
        "Conversation Name",
        "Sent At",
        "Received At",
        "Author",
        "Message",
        "Has Attachments?",
        "Is View Once?",
        "Is Erased?",
        "Expires At",
        "Message Status",
        "Has Reactions?",
        "Quoted Message ID",
        "Has Edit History?",
        "Last Edit Received At",
        "Author's Service ID",
        "Author's Device",
    ]

    MSGS_STATUSES_HEADERS = [
        "Message ID",
        "Target's Conversation ID",
        "Target's Name",
        "Message Status",
        "Status Timestamp",
    ]
    MSGS_VERSION_HISTS_HEADERS = ["Message ID", "Version Received At", "Body"]
    MSGS_REACTIONS_HEADERS = ["Message ID", "Reactor's Conversation ID", "Reactor's Name", "Reaction", "Timestamp"]
    MSGS_ATTACHMENTS_HEADERS = ["Message ID", "Type", "Path", "Original File Name", "Content Type"]

    GROUPS_CHANGES_HEADERS = [
        "Message ID",
        "Conversation ID",
        "Group ID",
        "Group Name",
        "Timestamp",
        "Author's Name",
        "Type",
        "Details",
        "Details in JSON",
        "Author's Service ID",
    ]  # TODO: Details -> Something better

    for msg_batch in fetch_batches_select(
        cursor,
        "SELECT id, type, conversationId, json, hasAttachments, hasFileAttachments, readStatus, seenStatus, sent_at, received_at_ms, expiresAt, body, isErased, isViewOnce, sourceServiceId, sourceDevice FROM messages WHERE type IN ('outgoing','incoming','group-v2-change','timer-notification', 'story')",
    ):
        messages_rows = defaultdict(list)
        msgs_statuses_rows = defaultdict(list)
        msgs_version_hists_rows = defaultdict(list)
        msgs_reactions_rows = defaultdict(list)
        msgs_attachments_rows = defaultdict(list)
        groups_changes_rows = defaultdict(list)
        convIdKeys = []

        for msg in msg_batch:
            (
                msgId,
                msgType,
                msgConvId,
                msgJsonStr,
                hasAttachments,
                hasFileAttachments,
                readStatus,
                seenStatus,
                sent_at,
                received_at_ms,
                msgExpiresAt,
                body,
                isErased,
                isViewOnce,
                sourceServiceId,
                sourceDevice,
            ) = msg
            convIdKey = msgConvId if not args.merge_conversations else None
            if convIdKey not in convIdKeys:
                convIdKeys.append(convIdKey)
            try:
                msgJson = json.loads(msgJsonStr)

                msgConvType = convId2conv.get(msgConvId, {}).get("type", "")
                msgConvName = convId2conv.get(msgConvId, {}).get("name", "")
                msgAuthorServiceId = sourceServiceId
                msgAuthor = service2name.get(msgAuthorServiceId, "")

                if msgType in ("outgoing", "incoming", "timer-notification", "story"):
                    # Message body handling
                    msgBody = process_message_bodyranges(msgJson, body)

                    # Message view state handling
                    msgStatus = ""
                    if msgType == "incoming":
                        if readStatus == 0 and seenStatus == 2:
                            msgStatus = "Read"
                        elif readStatus == 1 and seenStatus == 1:
                            msgStatus = "Unread"
                        elif readStatus == 2 and seenStatus == 2:
                            msgStatus = "Viewed"
                        else:
                            # This should not happen
                            msgStatus = f"UNKNOWN (readStatus: {readStatus} | seenStatus: {seenStatus})"
                    elif msgType == "outgoing" or msgType == "story":
                        if msgAuthorServiceId is None:
                            msgAuthorServiceId = myServiceId
                            msgAuthor = service2name.get(msgAuthorServiceId, "")
                        sendStateByConversationId = msgJson.get("sendStateByConversationId", {})
                        if msgConvType == "private" and msgType != "story":
                            msgStatus = sendStateByConversationId.get(msgConvId, {}).get("status", None)
                        elif msgConvType == "group" or msgType == "story":
                            firstValStatus = None
                            msgStatus = None
                            for cId, value in reversed(sendStateByConversationId.items()):

                                valStatus = value.get("status", None)
                                valUpdatedAt = value.get("updatedAt", None)
                                targetName = convId2conv.get(cId, {}).get("name", "")
                                msgs_statuses_rows[convIdKey].append(
                                    [msgId, cId, targetName, valStatus, tts(valUpdatedAt)]
                                )  # REVIEW: Also include E164?

                                if valStatus in ("Pending", "Sent"):
                                    continue  # This is the state of the sending user
                                if firstValStatus == None:
                                    firstValStatus = valStatus
                                    msgStatus = valStatus + " by all"
                                elif firstValStatus != valStatus:
                                    msgStatus = "..."  # NOTE: Explain this
                                    break

                    # Message version history handling
                    msgEditHistory = msgJson.get("editHistory", [])
                    hasEditHistory = len(msgEditHistory) > 0
                    msgLastEditReceivedAt = msgJson.get("editMessageReceivedAtMs", None)

                    for version in msgEditHistory:
                        msgs_version_hists_rows[convIdKey].append(
                            [
                                msgId,
                                tts(version.get("received_at_ms", None)),
                                process_message_bodyranges(version),
                            ]
                        )

                    # Message reactions handling
                    msgReactions = msgJson.get("reactions", [])

                    for reaction in msgReactions:
                        reactorConvId = reaction.get("fromId", None)
                        reactorName = convId2conv.get(reactorConvId, {}).get("name", "")
                        msgs_reactions_rows[convIdKey].append(
                            [
                                msgId,
                                reactorConvId,
                                reactorName,
                                reaction.get("emoji", None),
                                tts(reaction.get("timestamp", None)),
                            ]
                        )

                    # Handle attachments
                    hasReactions = len(msgReactions) > 0
                    hasPreview = "preview" in msgJson and "image" in msgJson["preview"]

                    if hasAttachments or hasFileAttachments:
                        attachments = msgJson.get("attachments", [])
                        for attachment in attachments:
                            attContType = attachment.get("contentType", None)
                            if msgType == "story" and attContType == "text/x-signal-story":
                                msgBody = attachment.get("textAttachment", {}).get("text", "")
                            else:
                                msgs_attachments_rows[convIdKey].append(
                                    [
                                        msgId,
                                        "attachment",
                                        attachment.get("path", None),
                                        attachment.get("fileName", None),
                                        attContType,
                                    ]
                                )
                    if hasPreview:
                        previews = msgJson.get("preview", [])
                        for preview in previews:
                            previewImg = preview.get("image", {})
                            msgs_attachments_rows[convIdKey].append(
                                [
                                    msgId,
                                    "preview",
                                    previewImg.get("path", None),
                                    None,
                                    previewImg.get("contentType", None),
                                ]
                            )

                    if "expirationTimerUpdate" in msgJson:
                        msgEtu = msgJson.get("expirationTimerUpdate", {})
                        expireTimer = msgEtu.get("expireTimer", None)
                        msgAuthorServiceId = msgEtu.get("sourceServiceId", None)
                        msgAuthor = service2name.get(msgAuthorServiceId, "")
                        msgBody = (
                            f"{msgAuthor} updated the expiration timer to {str(expireTimer)} seconds"
                            if expireTimer is not None
                            else f"{msgAuthor} disabled the expiration timer"
                        )

                    quotedMessageId = msgJson.get("quote", {}).get("messageId", None)

                    messages_rows[convIdKey].append(
                        [
                            msgId,
                            msgType,
                            msgConvId,
                            msgConvType,
                            msgConvName,
                            tts(sent_at),
                            tts(received_at_ms),
                            msgAuthor,
                            msgBody,
                            (hasAttachments or hasFileAttachments or hasPreview) == 1,
                            isViewOnce == 1,
                            isErased == 1,
                            tts(msgExpiresAt),
                            msgStatus,
                            hasReactions,
                            quotedMessageId,
                            hasEditHistory,
                            tts(msgLastEditReceivedAt),
                            msgAuthorServiceId,
                            sourceDevice,
                        ]
                    )
                elif msgType == "group-v2-change":
                    msgGrpChange = msgJson.get("groupV2Change", {})
                    gcDetails = msgGrpChange.get("details", [])

                    for gcDetail in gcDetails:
                        gcType = gcDetail.get("type", None)
                        detailsText = details_to_text(gcDetail)

                        groups_changes_rows[convIdKey].append(
                            [
                                msgId,
                                msgConvId,
                                conv2group.get(msgConvId, None),
                                convId2conv.get(msgConvId, {}).get("name", ""),
                                tts(msgJson.get("received_at_ms", None)),
                                msgAuthor,
                                gcType,
                                detailsText,
                                json.dumps(gcDetail) if gcDetail is not None else None,
                                msgAuthorServiceId,
                            ]
                        )

            except Exception as e:
                log(f"[!] Failed to process message {msgId}: {e}", 3)

        def append_to_reports(name, reportLocation, headers, rows):
            if not write_csv_file(reportLocation.with_suffix(".csv"), headers, rows):
                log(f"[!] Failed to write to the {name} CSV file")

        # Append to the csv files
        for kConvId in convIdKeys:
            if not kConvId in messages_rows and not kConvId in groups_changes_rows:
                continue
            reportFolder = reports_folder
            suffix = ""
            if not args.merge_conversations:
                reportFolder = reportFolder / kConvId
                suffix = "_" + kConvId
                reportFolder.mkdir(parents=True, exist_ok=True)

            append_to_reports("messages", reportFolder / f"messages{suffix}", MESSAGES_HEADERS, messages_rows[kConvId])

            append_to_reports(
                "messages statuses",
                reportFolder / f"outgoing_group_messages_statuses{suffix}",
                MSGS_STATUSES_HEADERS,
                msgs_statuses_rows[kConvId],
            )

            append_to_reports(
                "messages version histories",
                reportFolder / f"messages_version_histories{suffix}",
                MSGS_VERSION_HISTS_HEADERS,
                msgs_version_hists_rows[kConvId],
            )

            append_to_reports(
                "messages reactions",
                reportFolder / f"messages_reactions{suffix}",
                MSGS_REACTIONS_HEADERS,
                msgs_reactions_rows[kConvId],
            )

            append_to_reports(
                "messages attachments",
                reportFolder / f"messages_attachments{suffix}",
                MSGS_ATTACHMENTS_HEADERS,
                msgs_attachments_rows[kConvId],
            )

            append_to_reports(
                "group changes",
                reportFolder / f"groups_changes{suffix}",
                GROUPS_CHANGES_HEADERS,
                groups_changes_rows[kConvId],
            )

        # Free memory
        messages_rows.clear()
        msgs_statuses_rows.clear()
        msgs_version_hists_rows.clear()
        msgs_reactions_rows.clear()
        msgs_attachments_rows.clear()
        groups_changes_rows.clear()
        convIdKeys.clear()

    del messages_rows
    del msgs_statuses_rows
    del msgs_version_hists_rows
    del msgs_reactions_rows
    del msgs_attachments_rows
    del groups_changes_rows
    del convIdKeys

    call_history = select_sql(
        cursor,
        "SELECT callId, peerId, ringerId, mode, type, direction, status, timestamp, startedById, endedTimestamp FROM callsHistory;",
        "call logs",
    )

    if len(call_history) == 0:
        log("[i] No call logs were found in the database")
    else:
        CALLS_HEADERS = [
            "Call ID",
            "Peer's Name",
            "Call Initiator's Name",
            "Ringer's Name",
            "Mode",
            "Type",
            "Direction",
            "Status",
            "Timestamp",
            "Ended Timestamp",
            "Peer's ID",
            "Call Initiator's ID",
            "Ringer's ID",
        ]
        calls_rows = []
        for call in call_history:
            callId, peerId, ringerId, mode, callType, direction, status, timestamp, startedById, endedTimestamp = call
            peerName = service2name.get(peerId, "") if mode == "Direct" else group2name.get(peerId, "")
            if mode == "Direct":
                ringerId = peerId if direction == "Incoming" else user_uuid
            callInitiatorName = service2name.get(startedById, "")
            ringerName = service2name.get(ringerId, "")

            calls_rows.append(
                [
                    str(callId),
                    peerName,
                    callInitiatorName,
                    ringerName,
                    mode,
                    callType,
                    direction,
                    status,
                    tts(timestamp),
                    tts(endedTimestamp),
                    peerId,
                    startedById,
                    ringerId,
                ]
            )
        if not write_csv_file(reports_folder / "calls_history.csv", CALLS_HEADERS, calls_rows):
            log("[!] Failed to write the calls history CSV file")


####################### MISC HELPER FUNCTIONS #######################


# Converts a timestamp to a localized string
def localize_timestamp(timestamp, args: argparse.Namespace, ms=True):
    """Converts a timestamp to a localized string."""
    tzStr = args.convert_timestamps
    if not tzStr:
        return timestamp
    if ms:
        timestamp = int(timestamp / 1000)
    try:
        dt = datetime.fromtimestamp(timestamp, pytz.timezone(tzStr))
        return dt.strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception as e:
        log(f"[!] Failed to localize timestamp {timestamp}: {e}", 3)
    return timestamp


def generate_db_name(length=8, prefix="signal"):
    """Generates a random database name."""
    return f"{prefix}_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


####################### HEADER #######################
def print_config(args: argparse.Namespace):
    """Prints the script's current configuration."""
    log("----------------------==<[ CONFIG ]>==----------------------")
    log(f"Mode: {args.mode}")
    log(f"Environment: {args.env}")
    log(f"Signal Directory: {args.dir}")
    if args.output:
        log(f"Output Directory: {args.output}")
    log("------------------------------------------------------------")


####################### MAIN FUNCTION #######################


def main():
    log(f"SignalDecryptor v{VERSION} by @gonssalu")

    # Parse and validate arguments
    args = parse_args()
    validate_args(args)

    print_config(args)

    # Setup logging
    su.quiet = args.quiet
    su.verbose = args.verbose

    # Initialize decryption key
    decryption_key = None

    # Fetch the decryption key
    if args.mode == "key":
        log("[i] Fetching decryption key...", 1)
        decryption_key = fetch_key_from_args(args)
        log(f"> Decryption Key: {bytes_to_hex(decryption_key)}", 2)
        log("[i] Decryption key loaded", 1)
    else:
        log("[i] Fetching auxiliary key...", 1)
        aux_key = fetch_aux_key(args)
        log(f"> Auxiliary Key: {bytes_to_hex(aux_key)}", 2)
        correct_aux_key_length = 32 if args.env == "windows" else 16
        if not aux_key or len(aux_key) != correct_aux_key_length:
            raise MalformedKeyError(f"The auxiliary key is not {correct_aux_key_length} bytes long.")
        log("[i] Auxiliary key loaded", 1)

        log("[i] Decrypting the decryption key...", 1)
        decryption_key = fetch_decryption_key(args, aux_key)
        log(f"[i] SQLCipher Key: {bytes_to_hex(decryption_key)}")

    # Skip all decryption if requested
    if args.no_decryption:
        return

    # Decrypt and process the SQLCipher database
    log("[i] Opening SQLCipher database")
    db_conn, db_cursor = open_sqlcipher_db(args, decryption_key)

    # Attachments decryption
    if not args.skip_attachments:
        log("[i] Exporting attachments...")
        export_attachments(db_cursor, args)

    # Generate CSV reports
    if not args.skip_reports:
        log("[i] Writing reports...")
        process_database_and_write_reports(db_cursor, args)
        generate_html_report(args)

    # Close the database connection
    log("Closing the database connections...", 3)
    db_cursor.close()
    db_conn.close()

    return


if __name__ == "__main__":
    main()
