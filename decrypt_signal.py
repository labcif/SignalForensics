import argparse

# Parse command line arguments
parser = argparse.ArgumentParser(description='Decrypts the forensic artifacts from Signal Desktop on Windows') # TODO: Better usage message

# IO arguments
parser.add_argument('-d', '--dir', help='Path to Signal\'s directory', required=True) # TODO: Turn this into an optional argument
parser.add_argument('-o', '--output', help='Path to the output directory', required=True)
parser.add_argument('-c', '--config', help='Path to the Signal\'s configuration file')
parser.add_argument('-l', '--local-state' , help='Path to the Signal\'s Local State file')

# TODO: DPAPI argument

# Operational arguments
parser.add_argument('-sA', '--skip-attachments', help='Skip attachment decryption', action='store_true')
parser.add_argument('-g', '--generate-report', help='Generate a report', action='store_true') # TODO: Expand this to include different types of reports

# Verbosity arguments
parser.add_argument('-v', '--verbose', help='Enable verbose output', action='store_true')
parser.add_argument('-q', '--quiet', help='Enable quiet output', action='store_true')

# Informational arguments
parser.add_argument('-V', '--version', help='Print the version of the script', action='store_true')



parser.print_help()