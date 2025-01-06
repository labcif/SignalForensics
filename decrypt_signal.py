import argparse
import pathlib
import os
import json
import base64
import uuid
import random
import string
import mimetypes
import sys
import csv

import sqlcipher3

from modules import shared_utils as su
from modules.shared_utils import bytes_to_hex, log, MalformedKeyError
from modules.crypto import aes_256_gcm_decrypt, aes_256_cbc_decrypt, hash_sha256

####################### CONSTANTS #######################
VERSION = "1.0"

AUX_KEY_PREFIX = "DPAPI"

DEC_KEY_PREFIX = "v10"

DPAPI_BLOB_GUID = uuid.UUID("df9d8cd0-1501-11d1-8c7a-00c04fc297eb")

####################### EXCEPTIONS #######################


class MalformedInputFileError(Exception):
    """Exception raised for a malformed input file."""

    pass


####################### I/O ARGS #######################


# Parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser(
        prog="SignalDecryptor",
        description="Decrypts the forensic artifacts from Signal Desktop on Windows",
        usage="""%(prog)s [-m auto] -d <signal_dir> [-o <output_dir>] [OPTIONS]
        %(prog)s -m aux -d <signal_dir> [-o <output_dir>] [-kf <file> | -k <HEX>] [OPTIONS]
        %(prog)s -m key -d <signal_dir> -o <output_dir> [-kf <file> | -k <HEX>] [OPTIONS]
        %(prog)s -m manual -d <signal_dir> [-o <output_dir>] -wS <SID> -wP <password> [OPTIONS]
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
            "Mode of execution (choices: 'auto' for Windows Automatic, 'aux' for Auxiliary Key Provided, "
            "'key' for Decryption Key Provided), 'manual' for Windows Manual. "
            "Short aliases: -mA (Auto), -mAK (Auxiliary Key), -mDK (Decryption Key), -mM (Manual)"
            "Default: auto"
        ),
        type=parse_mode,
        choices=["auto", "aux", "key", "manual"],
        metavar="{auto|aux|key|manual}",
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

    # DPAPI related arguments
    # manual_group = parser.add_argument_group("Windows Manual Mode", "Arguments required for manual mode.")
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
    parser.add_argument("-sR", "--skip-reports", help="Skip the generation of CSV reports", action="store_true")
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
    if not args.output:
        if not args.no_decryption:
            log("[!] No output directory provided, assuming no decryption is required")
        args.no_decryption = True
    elif not args.output.is_dir():
        try:
            os.makedirs(args.output)
        except OSError as e:
            raise FileNotFoundError(f"Output directory '{args.output}' does not exist and could not be created.") from e

    # Validate auto mode
    if args.mode == "auto":
        if not sys.platform.startswith("win"):
            raise OSError("Automatic mode is only available on Windows.")

    # Validate manual mode arguments
    if args.mode == "manual":
        if not args.windows_sid:
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

    # If mode is Key Provided and skip decryption is enabled, raise an error
    if args.mode == "key" and args.skip_decryption:
        raise ValueError("Decryption cannot be skipped when providing the decryption key.")


####################### KEY FETCHING #######################


def fetch_key_from_args(args: argparse.Namespace):
    # If a key file is provided, read the key from the file
    if args.key_file:
        log("Reading the key from the file...", 2)
        with args.key_file.open("r") as f:
            return bytes.fromhex(f.read().strip())
    return args.key


def fetch_aux_key(args: argparse.Namespace):
    # If the user provided the auxiliary key, return it
    if args.mode == "aux":
        return fetch_key_from_args(args)
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

            # Check if this is a DPAPI blob
            if encrypted_key[4:20] != DPAPI_BLOB_GUID.bytes_le:
                raise MalformedKeyError("The encrypted auxiliary key is not in the expected DPAPI BLOB format.")

            if args.mode == "auto":
                try:
                    from modules import windows as win
                except ImportError as e:
                    raise ImportError("Windows-specific module could not be imported:", e)
                return win.unprotect_with_dpapi(encrypted_key)
            elif args.mode == "manual":
                from modules import manual as manual_mode  # REVIEW: Should this be imported here or at the top?

                return manual_mode.unprotect_manually(encrypted_key, args.windows_sid, args.windows_password)
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

        # Check if the key has the expected prefix
        if key[: len(DEC_KEY_PREFIX)] != DEC_KEY_PREFIX.encode("utf-8"):
            raise MalformedKeyError("The encrypted decryption key does not start with the expected prefix.")
        key = key[len(DEC_KEY_PREFIX) :]

        log("Processing the encrypted decryption key...", 2)

        nonce = key[:12]  # Nonce is in the first 12 bytes
        gcm_tag = key[-16:]  # GCM tag is in the last 16 bytes
        key = key[12:-16]

        log(f"> Nonce: {bytes_to_hex(nonce)}", 3)
        log(f"> GCM Tag: {bytes_to_hex(gcm_tag)}", 3)
        log(f"> Key: {bytes_to_hex(key)}", 3)

        log("Decrypting the decryption key...", 2)
        decrypted_key = aes_256_gcm_decrypt(aux_key, nonce, key, gcm_tag)

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


def write_csv_file(path, headers, rows):
    try:
        with open(path, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)

            writer.writeheader()
            for row in rows:
                writer.writerow(row)
    except Exception as e:
        log(f"[!] Failed to write CSV file: {e}")
        return False
    return True


def select_sql(cursor, statement, name=None):
    if name is not None:
        log(f"[i] Fetching all {name}...", 2)
    try:
        cursor.execute(statement)
        arr = cursor.fetchall()
        if name is not None:
            log(f"[i] Found {len(arr)} {name}", 1)
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


def process_database_and_write_reports(cursor, args: argparse.Namespace):

    log("[i] Processing the database...", 1)
    conversations = select_sql(
        cursor,
        "SELECT id, json, type, active_at, serviceId, profileFullName, e164 FROM conversations;",
        "conversations",
    )

    if len(conversations) == 0:
        log("[i] No conversations were found in the database")
        return

    # Create CSV headers and row arrays
    CONVERSATIONS_HEADERS = [
        "ID",
        "Type",
        "Name",
        "Last Active At",
        "Unread Messages",
        "Total Message Count",
        "Sent Message Count",
        "Last Message Author",
        "Last Message",
        "Last Message Deleted For Everyone",
        "Draft Message",
        "Expire Timer (seconds)",
        "Is Archived?",
        "Added By",
    ]
    CONTACTS_HEADERS = ["Conversation ID", "Name", "E164", "Profile Name", "Service ID"]
    GROUPS_MEMBERS_HEADERS = [
        "Conversation ID",
        "Name",
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
    conv2service = {}  # Dictionary of conversation ID to service ID
    convId2conv = {}  # Dictionary of conversation ID to name and type

    # Print mentions in the message
    def print_mentions_in_message(text, bodyRanges):
        if bodyRanges is None or text is None or type(bodyRanges) is not list:
            return text

        # Only include mentions, remove other bodyRanges
        bodyRanges = filter(lambda x: "mentionAci" in x, bodyRanges)

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

    # Process the last message with prefix and mentions.
    def process_last_message(convJson):
        last_message = print_mentions_in_message(
            convJson.get("lastMessage", None), convJson.get("lastMessageBodyRanges", None)
        )
        prefix = convJson.get("lastMessagePrefix", "")
        if prefix:
            last_message = f"{prefix} {last_message}"
        return last_message

    # Process group members and add to group_members_rows.
    def process_group_members(convId, convJson, group_members_rows):
        # TODO: """Process group members and add to group_members_rows."""
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
                mbrServiceId = member["aci"]
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

    # Populate the service2name dictionary
    for conv in conversations:
        convJson = json.loads(conv[1])
        theName = convJson.get("name", "")
        if convType == "private":
            if theName == "":
                # If there is no "contact name" in the conversation JSON, use the profileFullName or e164
                theName = conv[5] if conv[5] is not None else conv[6]
            service2name[conv[4]] = theName
            conv2service[conv[0]] = conv[4]
        convId2conv[conv[0]] = {"name": theName, "type": convType}

    # Process conversations table data
    for conv in conversations:
        convId, convJsonStr, convType, convActiveAt, serviceId = conv[:5]
        convJson = json.loads(convJsonStr)
        convLastMsg = process_last_message(convJson)
        convDraft = print_mentions_in_message(convJson.get("draft", None), convJson.get("draftBodyRanges", None))

        if convType == "private":
            contacts_rows.append([convId, convJson.get("name", ""), conv[6], conv[5], serviceId])
        elif convType == "group":
            process_group_members(convId, convJson, group_members_rows)

        added_by = convJson.get("addedBy", None)

        # Append the conversation data to the CSV rows
        conv_rows.append(
            [
                convId,
                convType,
                convJson.get("name", ""),
                convActiveAt,
                convJson.get("unreadCount", 0),
                convJson.get("messageCount", 0),
                convJson.get("sentMessageCount", 0),
                convJson.get("lastMessageAuthor", None),
                convLastMsg,
                convJson.get("lastMessageDeletedForEveryone", None),
                convDraft,
                convJson.get("expireTimer", None),
                convJson.get("isArchived", False),
                service2name.get(added_by, None),
            ]
        )

    # Write the csv files
    if not write_csv_file(args.output / "conversations.csv", CONVERSATIONS_HEADERS, conv_rows):
        log("[!] Failed to write the conversations CSV file")
    if not write_csv_file(args.output / "contacts.csv", CONTACTS_HEADERS, contacts_rows):
        log("[!] Failed to write the contacts CSV file")
    if not write_csv_file(args.output / "groups_members.csv", GROUPS_MEMBERS_HEADERS, group_members_rows):
        log("[!] Failed to write the groups members CSV file")

    # Free memory
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
        "Message Status",
        "Expires At",
        "Has Edit History?",
        "Has Reactions?",
        "Author's Service ID",
        "Author's Device",
    ]

    MSGS_STATUSES_HEADERS = ["Message ID", "Target's Conversation ID", "Target's Name", "Message Status"]

    messages_rows = []
    msgs_statuses_rows = []

    for msg_batch in fetch_batches_select(
        cursor,
        "SELECT id, type, conversationId, json, hasAttachments, hasFileAttachments, readStatus, seenStatus FROM messages WHERE type IN ('outgoing','incoming','group-v2-change');",
    ):
        for msg in msg_batch:
            msgId, msgType, msgConvId, msgJsonStr, hasAttachments, hasFileAttachments, readStatus, seenStatus = msg
            msgJson = json.loads(msgJsonStr)

            msgConvType = convId2conv.get(msgConvId, {}).get("type", "")
            msgConvName = convId2conv.get(msgConvId, {}).get("name", "")
            msgAuthorServiceId = msgJson.get("sourceServiceId", None)
            msgAuthor = service2name.get(msgAuthorServiceId, "")

            # Message expiration handling
            expiresTimer = msgJson.get("expiresTimer", None)
            if expiresTimer is None:
                msgExpiresAt = None
            else:
                msgExpiresAt = msgJson.get("expirationStartTimestamp", None) + (expiresTimer * 1000)

            # Message body handling
            msgBodyRanges = msgJson.get("bodyRanges", [])
            msgBody = msgJson.get("body", None)
            if len(msgBodyRanges) > 0:
                msgBody = print_mentions_in_message(msgBody, msgBodyRanges)

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
            elif msgType == "outgoing":
                sendStateByConversationId = msgJson.get("sendStateByConversationId", {})
                if msgConvType == "private":
                    msgStatus = sendStateByConversationId.get(msgConvId, {}).get("status", None)
                elif msgConvType == "group":
                    firstValStatus = None
                    msgStatus = None
                    for cId, value in sendStateByConversationId.items():

                        valStatus = value.get("status", None)
                        targetName = convId2conv.get(cId, {}).get("name", "")
                        msgs_statuses_rows.append([msgId, cId, targetName, valStatus])  # REVIEW: Also include E164?

                        if valStatus in ("Pending", "Sent"):
                            continue
                        if firstValStatus == None:
                            firstValStatus = valStatus
                            msgStatus = valStatus + " by all"
                        elif firstValStatus != valStatus:
                            msgStatus = "..."  # NOTE: Explain this
                            break

            messages_rows.append(
                msgId,
                msgType,
                msgConvId,
                msgConvType,
                msgConvName,
                msgJson.get("sent_at", None),
                msgJson.get("received_at", None),
                msgAuthor,
                msgBody,
                hasAttachments or hasFileAttachments,
                msgJson.get("isViewOnce", False),
                msgJson.get("isErased", False),
                msgStatus
                msgExpiresAt,
                msgAuthorServiceId,
                msgJson.get("sourceDevice", None),
            )

    # Write the csv files
    if not write_csv_file(args.output / "messages.csv", MESSAGES_HEADERS, messages_rows):
        log("[!] Failed to write the messages CSV file")
    if not write_csv_file(args.output / "messages_statuses.csv", MSGS_STATUSES_HEADERS, msgs_statuses_rows):
        log("[!] Failed to write the messages statuses CSV file")


def export_attachments(cursor, args: argparse.Namespace):
    attachments_dir = args.output / "attachments"
    attachments_dir.mkdir(parents=True, exist_ok=True)

    # Fetch all attachment data
    log("[i] Fetching attachment metadata...", 2)
    try:
        cursor.execute(
            "SELECT json from messages WHERE hasFileAttachments = TRUE OR hasAttachments = TRUE OR json LIKE '%\"preview\":[{%';"
        )
        messages = cursor.fetchall()
    except sqlcipher3.DatabaseError as e:
        raise sqlcipher3.DatabaseError("Failed to fetch attachment metadata.") from e

    if len(messages) == 0:
        log("[i] No attachments were found in the database")
        return

    # Process each attachment
    log("[i] Processing metadata and decrypting attachments...", 2)
    counts = 0
    error = 0
    integrity_error = 0
    for entry in messages:
        # Parse the message metadata
        msgJson = json.loads(entry[0])
        attachments = msgJson.get("attachments", [])

        # Preview of embed urls
        if "preview" in msgJson and "image" in msgJson["preview"]:
            attachments.append(msgJson["preview"]["image"])

        # For each attachment in the message
        for attachment in attachments:
            subpath = attachment["path"]
            try:
                # Fetch attachment crypto data
                key = base64.b64decode(attachment["localKey"])[:32]
                nonce = base64.b64decode(attachment["iv"])
                size = int(attachment["size"])

                # Encrypted attachment path
                enc_attachment_path = args.dir / "attachments.noindex" / subpath

                # Check if the encrypted attachment is present on the expected path
                if not enc_attachment_path.is_file():
                    log(f"[!] Attachment {subpath} not found", 2)
                    error += 1
                    continue

                # Fetch attachment cipherdata
                with enc_attachment_path.open("rb") as f:
                    enc_attachment_data = f.read()

                # Decrypt the attachment
                attachment_data = aes_256_cbc_decrypt(key, nonce, enc_attachment_data)
                attachment_data = attachment_data[16 : 16 + size]  # Dismiss the first 16 bytes and the padding
                if bytes.fromhex(attachment["plaintextHash"]) != hash_sha256(attachment_data):
                    log(f"[!] Attachment {subpath} failed integrity check", 2)
                    integrity_error += 1

                # Save the attachment to a file
                filePath = subpath
                if "contentType" in attachment:
                    filePath += f"{mime_to_extension(attachment['contentType'])}"

                # Ensure the parent directory exists
                attachment_path = attachments_dir / filePath
                attachment_path.parent.mkdir(parents=True, exist_ok=True)
                with attachment_path.open("wb") as f:
                    f.write(attachment_data)

                counts += 1
            except Exception as e:
                error += 1
                log(f"[!] Failed to export attachment {subpath}: {e}", 3)

    log(f"[i] Exported {counts} attachments")
    if integrity_error > 0:
        log(f"[!] {integrity_error} attachments failed integrity check")
    if error > 0:
        log(f"[!] Failed to export {error} attachments")


####################### MISC HELPER FUNCTIONS #######################


def generate_db_name(length=8, prefix="signal"):
    return f"{prefix}_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def mime_to_extension(mime_type):
    extension = mimetypes.guess_extension(mime_type)
    return extension


####################### HEADER #######################
def print_config(args: argparse.Namespace):
    log("----------------------==<[ CONFIG ]>==----------------------")
    log(f"Mode: {args.mode}")
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
        if not aux_key or len(aux_key) != 32:
            raise MalformedKeyError("The auxiliary key is not 32 bytes long.")
        log(f"> Auxiliary Key: {bytes_to_hex(aux_key)}", 2)
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

    # Close the database connection
    log("Closing the database connections...", 3)
    db_cursor.close()
    db_conn.close()

    return


if __name__ == "__main__":
    main()
