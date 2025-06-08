import secretstorage
from modules.shared_utils import log


def gnome_get_aux_key_passphrase_live() -> bytes:
    """Fetches the passphrase required to derive the auxiliary key for Signal from GNOME Keyring using live D-Bus connection."""
    log("Fetching the passphrase from GNOME Keyring...", 2)
    connection = secretstorage.dbus_init()
    collections = secretstorage.get_all_collections(connection)
    if not collections:
        raise ValueError("No collections found in GNOME Keyring. Could not retrieve the required passphrase.")

    log(f"Searching all collections in GNOME Keyring...", 3)
    for collection in collections:
        items = collection.get_all_items()
        for item in items:
            try:
                if item.get_attributes().get("application") != "Signal":
                    continue
                secret = item.get_secret()
                log(f"> Passphrase: {secret.decode('utf-8')}", 3)
                return secret
            except Exception:
                continue
