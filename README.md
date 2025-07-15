# SignalForensics

SignalForensics is a Python-based forensic tool that automates the decryption and extraction of data from **Signal Desktop**'s local files. It also produces structured CSV and HTML reports for easy analysis or integration with other tools.

SignalForensics is fully automated when run in the same Windows environment as Signal Desktop, but also includes flexible execution modes that adapt to different scenarios and operating systems with varying levels of user input.

This project is based on the work done in the article titled "Decrypting Messages: Extracting Digital Evidence from Signal Desktop for Windows" (dated _TBD_). For a deeper understanding of Signal's data structures and artifacts, as well as the decryption process, we highly recommend checking it out. It provides valuable context and detailed explanations that complement the functionality of this script.

---

## 🚀 Features

- Automated decryption of Signal Desktop artifacts
- Multiple execution modes and support for different environments
- CSV and HTML report generation
- Quiet mode and customizable verbosity
- Optional skipping of decryption/report steps

---

## 📦 Installation

SignalForensics uses [Poetry](https://python-poetry.org/) for dependency management.

1. Clone the repository:
   ```bash
   git clone https://github.com/labcif/SignalForensics
   cd SignalForensics
   ```
2. Install dependencies:
   ```bash
   poetry install
   ```

---

## 🛠️ Pre-built Version

In the [Releases](https://github.com/labcif/SignalForensics/releases), you'll find a `.pyz` version of the script. This self-contained archive is built using the `build.bat` script and bundles all the modules into a single file.

To run the `.pyz` version:

```bash
python SignalForensics.pyz -h
```

---

## 🧑‍💻 Execution Modes and Environments

SignalDecryptor supports four execution modes:

- **Live** (`-m live`)  
  In this mode, the script attempts to decrypt Signal's auxiliary key using operating system–specific services available on the machine where Signal Desktop was originally used.

  - On **Windows**, it uses DPAPI to decrypt the key directly from the `Local State` file.
  - On **GNOME (Linux)**, it accesses the key via the GNOME Keyring, using the currently logged-in user session.
  - This mode requires execution **within the original user account and environment** (same machine and OS profile as Signal Desktop).

- **Forensic** (`-m forensic`)  
  This mode allows analysts to decrypt Signal artifacts **outside the original system**, provided they have access to:

  - The GNOME Keyring file (usually `login.keyring`)
  - The user's master password (or its raw hex form)  
    The script uses these to derive the auxiliary key and subsequently decrypt the SQLCipher key.
    > ⚠️ This mode is currently not available for **Windows**.

- **Auxiliary Key Provided** (`-m aux`)  
  In this mode, the user manually supplies the **auxiliary key** (either directly via `--key` or via a file with `--key-file`).  
  The script then decrypts the SQLCipher key stored in Signal's `config.json` using this auxiliary key.  
  This allows full offline decryption of databases and attachments, without needing access to OS-specific secrets or Keyring.

- **SQLCipher Key Provided** (`-m key`)  
  In this mode, the user provides the **SQLCipher key** (the key that directly decrypts Signal’s database).  
  This bypasses the need to decrypt anything from the `config.json` or derive keys, as the script uses the supplied key immediately to decrypt the database and extract artifacts.

  > ⚠️ This mode assumes you already possess the exact SQLCipher key used by Signal.

- **Passphrase Provided** (`-m passphrase`)  
  Accepts the passphrase stored in the GNOME Keyring.  
  SignalDecryptor will use this string to derive the auxiliary key and decrypt artifacts.  
  Useful when you have already extracted the passphrase from the keyring structure itself.
  > ⚠️ This mode is currently only supported for Linux GNOME environments.

### Required Environment Flag

Each mode requires you to specify the **environment** from which the Signal data was acquired, using the `--env` or `-e` argument. Currently supported environments are:

- `windows`: Standard Signal Desktop installation on Windows
- `gnome`: Signal Desktop installation on Linux using GNOME Keyring
- `linux`: Signal Desktop installation on Linux without a OS-level keystore library (e.g Libsecret)

### Compatibility Matrix

| Execution Mode         | Windows | GNOME | Linux |
| ---------------------- | ------- | ----- | ----- |
| Live                   | ✅      | ✅    | ➖    |
| Forensic               | ❌      | ✅    | ✅    |
| Auxiliary Key Provided | ✅      | ✅    | ✅    |
| SQLCipher Key Provided | ✅      | ✅    | ✅    |
| Passphrase Provided    | ❌      | ✅    | ❌    |

> ⚠️ **Note:** In Linux environments without a OS-level keystore library, Live mode behaves identically to Forensic mode, as no secure key retrieval via the operating system is required.

---

## 🧑‍💻 Usage

**Basic syntax:**

```bash
SignalForensics [-m live] [-e <environment>] -d <signal_dir> [-o <output_dir>] [OPTIONS]
SignalForensics -m forensic -e <environment> -d <signal_dir> [-o <output_dir>] [-p <password> | -pb <HEX> | -pbf <file>] -gkf <gnome_keyring_file> [OPTIONS]
SignalForensics -m aux [-e <environment>] -d <signal_dir> [-o <output_dir>] [-kf <file> | -k <HEX>] [OPTIONS]
SignalForensics -m key [-e <environment>] -d <signal_dir> -o <output_dir> [-kf <file> | -k <HEX>] [OPTIONS]
SignalForensics -m passphrase -e <environment> -d <signal_dir> [-p <passphrase> | -pb <HEX> | -pbf <file>] [-o <output_dir>] [OPTIONS]
```

**Examples:**

- Live Mode:
  ```bash
  SignalForensics -m live -d "C:\Users\TheUser\AppData\Roaming\Signal" -o output_folder
  ```
- Forensic Mode:
  ```bash
  SignalDecryptor -m forensic -e gnome -d ~/.config/Signal \
  -p 123456 \
  -gkf ~/.local/share/keyrings/login.keyring \
  -o output_dir
  ```
- Auxiliary Key Provided Mode:
  ```bash
  SignalForensics -m aux -d signal_data/ -kf aux_key.txt -o output_folder
  ```
- SQLCipher Key Provided Mode:
  ```bash
  SignalForensics -m key -d signal_data/ -k 9a325c73... -o output_folder
  ```
- Passphrase Provided Mode:
  ```bash
  SignalForensics -m passphrase -d signal_data/ -p "vEq+XKoPekTsiU+nciF4" -o output_folder
  ```

### ⚙️ Options

| Option                         | Description                                                                              |
| ------------------------------ | ---------------------------------------------------------------------------------------- |
| `-nd`, `--no-decryption`       | Skip decryption and report generation (incompatible with `-m key`)                       |
| `-sD`, `--skip-database`       | Do not export the unencrypted database                                                   |
| `-sA`, `--skip-attachments`    | Skip decryption of attachments and avatars                                               |
| `-sR`, `--skip-reports`        | Skip CSV and HTML report generation                                                      |
| `-mc`, `--merge-conversations` | Merge message-related reports into single CSV files                                      |
| `-t`, `--convert-timestamps`   | Convert timestamps to human-readable format (defaults to UTC if no timezone is provided) |
| `-q`, `--quiet`                | Suppress log output                                                                      |
| `-v`, `-vv`, `-vvv`            | Set verbosity level                                                                      |

### 📂 Input/Output

- `-d`, `--dir`: Path to Signal's data directory
- `-o`, `--output`: Output directory (optional; disables decryption if not provided)
- `-m`, `--mode`: Execution mode (`live`, `forensic`, `aux`, or `key`)
- `-e`, `--env`: Environment where Signal was running (`windows` or `gnome`)
- `-kf`, `--key-file`: Path to file containing key as a hex string (for key provided modes)
- `-k`, `--key`: Provide key directly as a hex string (for key provided modes)
- `-gkf`, `--gnome-keyring-file`: Path to Gnome Keyring file (for forensic mode)
- `-p`, `--password`: Master password for Gnome Keyring (for forensic mode)
- `-pb`, `--password-bytes`: Provide password as a hex string (for forensic mode)
- `-pbf`, `--password-bytes-file`: Path to file containing password as a hex string (for forensic mode)

> ⚠️ The password options (`-p`, `-pb`, `-pbf`) are reused for passphrase provided mode, where they represent the passphrase used to derive the auxiliary key.

---

## 📄 Reports

SignalForensics generates:

- CSV reports for extracted messages, calls, and attachments
- HTML report providing an interactive interface for analysis

Example report:
![Example HTML Report](images/example_html_report.png)

---

## 📜 License

This project is open-source and licensed under the GNU General Public License Version 3. See the [LICENSE](LICENSE) file for details.
