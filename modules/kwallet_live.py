import dbus
from modules.shared_utils import log

APP_ID = "SignalForensics"
FOLDER = "Chromium Keys"
ENTRY = "Chromium Safe Storage"


def kwallet_get_aux_key_passphrase_live() -> bytes:
    """Fetches the passphrase required to derive the auxiliary key for Signal from KWallet using live D-Bus connection."""
    log("Fetching the passphrase from KWallet...", 2)

    bus = dbus.SessionBus()
    kwallet = bus.get_object("org.kde.kwalletd5", "/modules/kwalletd5")
    iface = dbus.Interface(kwallet, "org.kde.KWallet")

    # Get the local wallet's name
    wallet_name = iface.localWallet()

    # Open the wallet
    handle = iface.open(wallet_name, 0, APP_ID)

    if handle < 0:
        raise RuntimeError("Failed to open KWallet.")

    # Read the passphrase
    password = iface.readPassword(handle, FOLDER, ENTRY, APP_ID)
    if password == "" or password is None:
        raise ValueError("No passphrase found in KWallet. Could not retrieve the required passphrase.")
    log(f"> Passphrase: {password}", 3)
    return password.encode("utf-8")
