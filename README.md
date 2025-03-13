# Wazuh Agent Configuration Result (`wresult`)

## Overview

`wresult` provides the running configuration of a Wazuh agent by reconstructing how it applies ossec.conf and agent.conf. This tool is designed to support users for compliance reporting and troubleshooting, ensuring that teams can see the actual settings enforced on an agent.

> [!IMPORTANT]
> While Wazuh supports agents on systems other than Linux and Windows, such as MacOS, Solaris, HP UX, this tool is designed for Windows and Linux only.

## Why Use wresult?

### The Problem

Wazuh agents dynamically apply configurations:

- ossec.conf is loaded first (local settings).
- agent.conf is fetched from the Wazuh manager and applied sequentially, overriding or appending settings.
  - Conditional configurations, aka [Options](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html#options) (e.g., OS-specific, profile-based configurations) determine the final applied settings.
- There are internal options that amends the behaviors in an advanced manner. For agents, it is generally just the debug configuration. Since the original file `internal_options.conf` is overwritten on every update, there is the `local_internal_options.conf` file for overriding default behaviors. This is crucial on troubleshooting. And user needs to be aware of the deviances from the defaults.

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

> [!IMPORTANT]
> ⚠️ Requires Root/Admin Privileges
> Due to the Wazuh configuration files' permissions, run with sudo (Linux) or as an Administrator (Windows).
> But if you are testing against custom configuration files only using the hidden parameters, you don't need higher privileges.

> [!WARNING]
> ⚠️ `pipx` does not play well with `sudo`. Therefore, you need to run `sudo -i`, install `wresult` via `pipx`, and use as root.
> I could not manage to find out a workaround to install `wresult` as root and use it with `sudo`, unfortunately.
> If you find it, please let me know by creating an issue, PR or dropping an email.

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
wresult | jq .
```

🔹 View the exact applied settings in structured JSON, ideal for automation.

📌 Example: JSON Output in Linux

> TODO: Add GIF

📌 Example: JSON Output in Windows

> TODO: Add GIF

### Generate a Human-Readable Report

> TODO: Add GIF

```shell
wresult --output report.html
```

🔹 Generates an interactive HTML report with expandable sections.

📌 Example: Interactive HTML Report

> TODO: Add GIF

## Hidden Arguments

In order to support testing, the tool has provided hidden parameters that are not visible on the help menu. Yhe users must provide all 3 of them if needed. Otherwise, the tool will fall back to default locations for the undefined paths. This is designed to test and validate configuration changes with out breaking the agent.

They are subject to change and must be considered undocumented API.

```shell
--agent_conf_path (-ap): Custom path for agent.conf.
--ossec_conf_path (-op): Custom path for ossec.conf.
--client_keys_path (-ck): Custom path for client.keys file.
--local_internal_options_path (-li): Custom path for local_internal_options_path.conf file.
```

## License

This project is open-source and licensed under the MIT License.

## Thanks

I was considering a remake of the `gpresult` HTML report, but I came up with a better and easier solution thanks to [Maxim Maeder](https://maximmaeder.com/display-json-with-html-css-and-javascript). I took his example, and simplified for my use case and it worked brilliantly. Kudos to Maxim!
