import argparse
import os
import pandas as pd
import re
from jinja2 import Environment, DictLoader
from modules.shared_utils import log
from modules.shared_utils import mime_to_extension

TEMPLATES = {
    "report_template.html": """<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Report</title>
    <link
      href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/5.3.0/css/bootstrap.min.css"
      rel="stylesheet"
      integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM"
      crossorigin="anonymous"
    />
    <link
      href="https://cdn.datatables.net/v/bs5/jq-3.7.0/dt-2.2.2/cr-2.0.4/fh-4.0.1/r-3.0.4/datatables.min.css"
      rel="stylesheet"
      integrity="sha384-9kXxIkqaeTB2jlXfmYzLXIefzYGqX8RGgMbDg9+Roneo63NYnX/xPycCG3H/1cvf"
      crossorigin="anonymous"
    />

    <script
      src="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/5.3.0/js/bootstrap.bundle.min.js"
      integrity="sha384-geWF76RCwLtnZ8qwWowPQNguL3RmwHVBC9FhGdlKrxdiJJigb/j/68SIy3Te4Bkz"
      crossorigin="anonymous"
    ></script>
    <script
      src="https://cdn.datatables.net/v/bs5/jq-3.7.0/dt-2.2.2/cr-2.0.4/fh-4.0.1/r-3.0.4/datatables.min.js"
      integrity="sha384-UM0p7faWDVvD4vxGqXgVlWKb5yVNBtJabHeESJ0Iamwa5UoqMj8Kl5nvmm/38ZBr"
      crossorigin="anonymous"
    ></script>

    <style>
      body {
        font-family: Arial, sans-serif;
        display: flex;
        margin: 0;
        height: 100vh;
        overflow: hidden;
      }
      .sidebar {
        width: 250px;
        background-color: #333;
        color: white;
        padding: 10px;
        overflow-y: auto;
      }
      .content {
        flex: 1;
        padding: 20px;
        overflow-y: auto;
      }
      .table-container {
        display: none;
      }
      .active {
        display: block;
      }
      .accordion {
        background-color: #444;
        color: white;
        cursor: pointer;
        padding: 12px;
        width: 100%;
        text-align: left;
        border: none;
        outline: none;
        transition: background-color 0.2s ease;
        font-size: 16px;
      }
      .accordion:hover {
        background-color: #555;
      }
      .accordion:after {
        content: "\\25B6"; /* Right arrow */
        float: right;
        font-size: 14px;
        transition: transform 0.2s ease;
      }
      .accordion.active:after {
        content: "\\25BC"; /* Down arrow */
      }
      .panel {
        padding-left: 10px;
        display: none;
        overflow: hidden;
        background-color: #222;
      }
      .panel a {
        display: block;
        padding: 8px;
        color: white;
        text-decoration: none;
        border-bottom: 1px solid #444;
        cursor: pointer;
      }
      .panel a:hover {
        background-color: #444;
      }
      .sidebar-id {
        font-size: 0.75em;
        padding: 8px;
        color: #f0f0f0;
        background-color: #222;
        border-left: 4px solid #444;
        margin-bottom: 5px;
        cursor: default;
      }
      .table-container {
        display: none;
        overflow-x: auto;
        padding: 10px;
      }
    </style>
  </head>
  <body>
    <div class="sidebar">
      {% for category, data in categories.items() %}
      <button class="accordion">{{ data.display_name }}</button>
      <div class="panel">
        {% if category != 'General' %}
        <div class="sidebar-id">{{ category }}</div>
        {% endif %} {% for table_id, table_label in data.tables %}
        <a onclick="showTable('{{ table_id }}')">{{ table_label }}</a>
        {% endfor %}
      </div>
      {% endfor %}
    </div>

    <div class="content">
      {% for table_id, table_html in tables.items() %}
      <div id="{{ table_id }}" class="table-container">
        {{ table_html | safe }}
      </div>
      {% endfor %}
    </div>

    <script>
      // Handle sidebar toggle (collapsible)
      const acc = document.getElementsByClassName("accordion");
      for (let i = 0; i < acc.length; i++) {
        acc[i].addEventListener("click", function () {
          this.classList.toggle("active");
          const panel = this.nextElementSibling;
          if (panel.style.display === "block") {
            panel.style.display = "none";
          } else {
            panel.style.display = "block";
          }
        });
      }

      // Show table function
      function showTable(tableId) {
        $(".table-container").hide();
        $("#" + tableId).show();

        // Initialize DataTable with Bootstrap 5 styling
        $("#" + tableId + " table")
          .addClass("table table-bordered table-striped")
          .DataTable({
            destroy: true,
            autoWidth: false,
            scrollX: true,
            responsive: false,
            colReorder: true,
            fixedHeader: true,
            paging: true,
            lengthChange: true,
            searching: true,
            ordering: true,
            info: true,
            columnDefs: [{ targets: "_all", className: "dt-center" }],
            language: {
              search: "🔍", // Custom search icon
              lengthMenu: "Displaying _MENU_ entries per page",
              zeroRecords: "No entries found",
              info: "Displaying _START_ to _END_ of _TOTAL_ total entries",
              infoEmpty: "No available data",
              infoFiltered: "(filtered from _MAX_ total entries)",
              paginate: {
                first: "First",
                last: "Last",
                next: "Next",
                previous: "Previous",
              },
            },
          });
      }
    </script>
  </body>
</html>
"""
}


def generate_html_report(args: argparse.Namespace):
    # Paths
    DATA_DIR = args.output / "reports"
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

                csv_path = os.path.join(root, file)
                df = pd.read_csv(csv_path, skiprows=1)

                # Special handling for message_attachments: hyperlink the 3rd column
                if base_name == "messages_attachments" and df.shape[1] >= 3:

                    def make_link(path, mimetype):
                        if pd.isna(path):
                            return ""
                        safe_path = str(path).strip()
                        ext = mime_to_extension(mimetype) if not pd.isna(mimetype) else ""
                        return f'<a href="../attachments.noindex/{safe_path}{ext}" target="_blank">{safe_path}{ext}</a>'

                    df.iloc[:, 2] = [make_link(path, mimetype) for path, mimetype in zip(df.iloc[:, 2], df.iloc[:, 3])]
                    tables[table_id] = df.to_html(index=False, classes="display", border=0, escape=False)
                else:
                    tables[table_id] = df.to_html(index=False, classes="display", border=0)

                categories[category]["tables"].append((table_id, table_label))

    log("Generating HTML report...", 2)

    env = Environment(loader=DictLoader(TEMPLATES))
    template = env.get_template("report_template.html")

    html_output = template.render(categories=categories, tables=tables)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(html_output)
