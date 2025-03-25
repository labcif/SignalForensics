import argparse
import os
import pandas as pd
import re
from jinja2 import Environment, FileSystemLoader
from modules.shared_utils import log


def generate_html_report(args: argparse.Namespace):
    # Paths
    DATA_DIR = args.output / "reports"
    TEMPLATE_DIR = "./templates"
    OUTPUT_FILE = DATA_DIR / "full_report.html"
    CONVERSATIONS_FILE = os.path.join(DATA_DIR, "conversations.csv")

    # Custom labels for specific files
    file_labels = {
        "calls_history": "Call History",
        "contacts": "Signal Contacts",
        "conversations": "Conversations",
        "groups_members": "Group Members",
        "group_changes": "Group Changes",
        "messages": "Messages",
        "messages_attachments": "Message Attachments",
        "messages_reactions": "Message Reactions",
        "messages_version_histories": "Message Version Histories",
        "outgoing_group_messages_statuses": "Outgoing Group Message Statuses",
    }

    log("Parsing CSV reports for HTML generation...", 1)

    # Read conversation names from conversations.csv
    conversation_map = {}
    if os.path.exists(CONVERSATIONS_FILE):
        df_conversations = pd.read_csv(CONVERSATIONS_FILE, skiprows=1)
        for _, row in df_conversations.iterrows():
            conversation_map[str(row["ID"])] = row["Name"] if not pd.isna(row["Name"]) else str(row["ID"])

    categories = {}
    tables = {}

    pattern = re.compile(r"^(.*?)(?:_[0-9a-fA-F-]{36})?$")

    for root, _, files in os.walk(DATA_DIR):
        category = os.path.relpath(root, DATA_DIR)
        if category == ".":
            category = "General"

        display_name = conversation_map.get(category, category)

        if category not in categories:
            categories[category] = {"display_name": display_name, "tables": []}

        for file in files:
            if file.endswith(".csv"):
                # Extract base name using regex
                table_base = os.path.splitext(file)[0]
                match = pattern.match(table_base)
                if match:
                    base_name = match.group(1)
                else:
                    base_name = table_base

                table_id = f"{category}_{table_base}"

                table_label = file_labels.get(base_name, base_name.replace("_", " ").title())

                df = pd.read_csv(os.path.join(root, file), skiprows=1)
                tables[table_id] = df.to_html(index=False, classes="display", border=0)
                categories[category]["tables"].append((table_id, table_label))

    log("Generating HTML report...", 2)
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report_template.html")

    html_output = template.render(categories=categories, tables=tables)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(html_output)
