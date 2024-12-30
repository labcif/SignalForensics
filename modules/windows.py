import sys

if not sys.platform.startswith("win"):
    raise ImportError("This module can only be used on Windows.")

from modules.shared_utils import log
import win32crypt

####################### DPAPI #######################


def unprotect_with_dpapi(data: bytes):
    log("[i] Unprotecting the auxiliary key through DPAPI...", 1)
    try:
        _, decrypted_data = win32crypt.CryptUnprotectData(data)
        return decrypted_data
    except Exception as e:
        raise ValueError("Failed to unprotect the auxiliary key with DPAPI.") from e
