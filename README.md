# Wazuh Configuration Result (`wresult`)

## Overview

`wresult` provides the exact, running configuration of a Wazuh agent by reconstructing how it applies ossec.conf and agent.conf. This tool is essential for compliance reporting and troubleshooting, ensuring that teams can see the actual settings enforced on an agent.

## Why Use wresult?

### The Problem

Wazuh agents dynamically apply configurations:

- ossec.conf is loaded first (local settings).
- agent.conf is fetched from the Wazuh manager and applied sequentially, overriding or appending settings.
- Conditional rules (e.g., OS-specific, profile-based configurations) determine the final applied settings.

As a result:

🔹 Compliance teams struggle to verify required security policies

🔹 Security engineers face difficulties troubleshooting unexpected agent behavior.

🔹 Administrators need a way to see the configuration exactly as the agent applies it.

### The Solution

✅ Shows the real, running configuration—not just raw config files.

✅ Resolves conflicts—newer policies override older ones.

✅ Filters out irrelevant settings—only applicable rules are included.

✅ Saves time—eliminates manual inspection of multiple configuration files.


### Features

- Accurate Reconstruction – Mirrors how Wazuh agents process configurations.
- Conflict Resolution – Newer settings take precedence; others are appended.
- JSON Output – Machine-readable, structured for automation and jq processing.
- HTML Report – Interactive, easy-to-read configuration report.
- Supports Linux & Windows – Uses standard Wazuh configuration paths.

## Installation

`wresult` is designed for easy installation and execution via `pipx`.

```shell
pipx install https://codeload.github.com/zbalkan/wresult/zip/refs/heads/main
```

## Usage

CLI Output (JSON for Automation)

```shell
sudo wresult | jq
```

🔹 View the exact applied settings in structured JSON, ideal for automation.

📌 Example: JSON Output in Linux

> TODO: Add GIF

📌 Example: JSON Output in Windows

> TODO: Add GIF

Generate a Human-Readable Report

> TODO: Add GIF

sudo wresult --output report.html

> TODO: Add GIF

🔹 Generates an interactive HTML report with expandable sections.

📌 Example: Interactive HTML Report

> TODO: Add GIF

## Arguments

--output (-o): If specified, writes an HTML report instead of JSON to stdout.
--agent_conf_path (-ap) (optional for testing): Custom path for agent.conf.
--ossec_conf_path (-op) (optional for testing): Custom path for ossec.conf.
--agent_info_path (-ai) (optional for testing): Custom path for agent info file.

## Permissions

⚠️ Requires Root/Admin PrivilegesWazuh configuration files are restricted to administrators. Run with sudo (Linux) or as an Administrator (Windows):

```shell
sudo wresult
```

## License

This project is open-source and licensed under the MIT License.
