# Wazuh Configuration Result (`wresult`)

## Overview

`wresult` provides the running configuration of a Wazuh agent by reconstructing how it applies ossec.conf and agent.conf. This tool is designed to support users for compliance reporting and troubleshooting, ensuring that teams can see the actual settings enforced on an agent.

## Why Use wresult?

### The Problem

Wazuh agents dynamically apply configurations:

- ossec.conf is loaded first (local settings).
- agent.conf is fetched from the Wazuh manager and applied sequentially, overriding or appending settings.
  - Conditional configurations, aka [Options](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html#options) (e.g., OS-specific, profile-based configurations) determine the final applied settings.

As a result:

🔹 Compliance teams struggle to verify if required security policies are applied.

🔹 Security engineers face difficulties troubleshooting unexpected agent behavior.

🔹 Administrators need a way to see the configuration exactly as the agent applies it.

> [!NOTE]
> This is the same issue with Group Policies in Windows environments where multiple policies, including local policies can be applied and there is a non-trivial precedence process to combine them for the expected results. There, the solution is collecting the Resultant Set of Policies (RSoP) via `gpresult` command. Hence the tool, `wresult`.

### The Solution

✅ Shows the running configuration—not just raw config files.

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

```yaml
usage: wresult [-h] [--output OUTPUT]

Parse the Wazuh agent running configuration, print to stdout as JSON or save to an HTML file.

options:
  -h, --help            show this help message and exit
  --output OUTPUT, -o OUTPUT
                        Output file path
```

### CLI Output (JSON for Automation)

```shell
sudo wresult | jq
```

🔹 View the exact applied settings in structured JSON, ideal for automation.

📌 Example: JSON Output in Linux

> TODO: Add GIF

📌 Example: JSON Output in Windows

> TODO: Add GIF

### Generate a Human-Readable Report

> TODO: Add GIF

```shell
sudo wresult --output report.html
```

🔹 Generates an interactive HTML report with expandable sections.

📌 Example: Interactive HTML Report

> TODO: Add GIF

## Hidden Arguments

In order to support testing, tI provided hidden parameters
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
