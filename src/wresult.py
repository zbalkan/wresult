from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pathlib
import re
import sys
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime as dt
from datetime import timezone
from typing import Any

import xmltodict


class HtmlGenerator:
    def generate(self, agent_name: str, agent_id: str, json: str) -> str:
        template = """
<!DOCTYPE html>
<html lang="en">
<!-- Thanks to: https://maximmaeder.com/display-json-with-html-css-and-javascript/ -->
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wazuh Agent Configuration Result for NAME_PLACEHOLDER</title>
    <style>
        :root {
            --bg: rgb(255, 255, 255);
            --titleStyle: rgb(0, 0, 0);
            --string: rgb(96, 96, 100);
        }

        body {
            margin: 0;
            background-color: rgb(40, 40, 40);
        }

        ul {
            list-style-type: none;
            padding-inline-start: 20px;
        }

        pre {
            padding: 1em;
            margin: 0;
            background-color: var(--bg)
        }

        summary::marker {
            color: rgb(61, 130, 241);
        }

        li :hover {
            background-color: rgb(240, 191, 76);
            color: black;
        }

        .titleStyle {
            color: var(--titleStyle);
            user-select: none;
        }

        .content {
            flex: 1;
            background-color: rgb(180, 180, 180);
            max-width: 90%;
        }

        .string {
            color: var(--string);
            user-select: text;
        }

        .string::before,
        .string::after {
            content: '"';
            color: var(--string)
        }

        .navbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background-color: rgb(61, 130, 241);
            padding: 15px 20px;
            color: white;
            font-family: 'Segoe UI', 'DejaVu Sans', 'Arial', 'Liberation Sans', sans-serif;
        }

        .navbar-left {
            display: flex;
            flex-direction: column;
        }

        .navbar-title {
            font-size: 28px;
            font-weight: bold;
        }

        .navbar-left p {
            font-size: 14px;
            margin: 5px 0 0 0;
            font-family: monospace;
        }

        .navbar-links {
            display: flex;
            gap: 15px;
        }

        .navbar a {
            color: white;
            text-decoration: none;
            font-size: 12px;
        }

        .navbar a:hover {
            text-decoration: underline;
        }

        .footer {
            background-color: rgb(0, 0, 0);
            color: white;
            text-align: center;
            padding: 10px;
            position: relative;
            top: 0;
            width: 100%;
            height: 100%;
            font-size: 12px;
            font-family: 'Segoe UI', 'DejaVu Sans', 'Arial', 'Liberation Sans', sans-serif;
            border-top: 1px solid #444;
        }

        .footer a {
            font-weight: bold;
            color: white;
            text-decoration: none;
            text-transform: uppercase;
        }

        .footer a:hover {
            text-decoration: underline;
        }

        @media print {
        body {
            background: none !important;
            color: black;
            font-family: "Arial", sans-serif;
        }

        /* Keep navbar title and agent metadata */
        .navbar {
            display: block !important;
            background: none !important;
            color: black;
            text-align: center;
            border-bottom: 2px solid black;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }

        .navbar-title {
            font-size: 20px;
            font-weight: bold;
        }

        .navbar-left p {
            font-size: 14px;
            font-weight: normal;
            text-align: center;
            margin: 0;
        }

        /* Hide unnecessary UI elements */
        .navbar-links,
        .footer {
            display: none !important;
        }

        /* Expand all JSON sections automatically */
        details {
            display: block !important;
            margin-top: 5px;
        }

        details > summary {
            display: block !important;
            font-weight: bold;
        }

        /* Style JSON structure as hierarchical headers */
        details summary:nth-of-type(1) {
            font-size: 18px;
            font-weight: bold;
            text-transform: uppercase; /* 🔹 Your change: Makes top-level JSON keys uppercase */
        }

        details summary:nth-of-type(2) {
            font-size: 16px;
            font-weight: bold;
        }

        details summary:nth-of-type(3) {
            font-size: 14px;
            font-weight: bold;
        }

        details summary:nth-of-type(4) {
            font-size: 12px;
            font-weight: bold;
        }

        /* Ensure content fits well on A4 */
        @page {
            size: A4 portrait;
            margin: 20mm;
        }

        ul {
            padding: 0;
            margin: 0;
        }

        li {
            font-size: 12px;
            word-wrap: break-word;
        }

        /* Prevent content from breaking across pages */
        details,
        details summary,
        li {
            page-break-inside: avoid;
        }
    }
    </style>
</head>

<body>
    <script type="text/javascript">
        function expandAll() {
            document.querySelectorAll('details:not([open]) summary').forEach(summary => {
                summary.click();
                setTimeout(() => expandAll(), 10); // Recursively expand deeper levels
            });
        }

        function collapseAll() {
            document.querySelectorAll('details[open] summary').forEach(summary => {
                summary.click();
                setTimeout(() => collapseAll(), 10); // Recursively collapse deeper levels
            });
        }

        function wrapTextWithDelimiters(text, maxLength, delimiters = [' ', '|']) {
            let wrappedText = '';
            let start = 0;

            while (start < text.length) {
                let end = start + maxLength;

                if (end >= text.length) {
                    wrappedText += text.substring(start);
                    break;
                }

                let slice = text.substring(start, end + 1);

                let wrapAt = -1;
                for (let i = slice.length - 1; i >= 0; i--) {
                    if (delimiters.includes(slice[i])) {
                        wrapAt = start + i;
                        break;
                    }
                }

                if (wrapAt <= start || wrapAt === -1) {
                    wrapAt = end;
                    wrappedText += text.substring(start, wrapAt) + '\\n';
                    start = wrapAt;
                } else {
                    wrappedText += text.substring(start, wrapAt + 1) + '\\n';
                    start = wrapAt + 1;
                }
            }

            return wrappedText;
        }


        function renderJson({root = '', data, depth = 0} = {}) {
            const maxLength = 120;

            if (depth == 0 && root == '') {
                const pre = document.createElement('pre')
                const ul = document.createElement('ul')

                pre.appendChild(ul)
                root = ul
                document.body.appendChild(pre)
            }
            else {
                root.innerHTML = ''
            }

            for (d in data) {
                if (typeof data[d] == 'object' && data[d] != null) {
                    const nestedData = data[d]

                    const detailsElement = document.createElement('details')
                    const summaryEl = document.createElement('summary')
                    summaryEl.classList.add('titleStyle')

                    detailsElement.appendChild(summaryEl)

                    summaryEl.innerHTML = `${d}`

                    const newRoot = document.createElement('ul')

                    detailsElement.appendChild(newRoot)

                    root.appendChild(detailsElement)

                    summaryEl.addEventListener('click', () => {
                        if ( !detailsElement.hasAttribute('open') ) {
                            renderJson({
                                    root: newRoot,
                                    data: nestedData,
                                    depth: depth + 1
                                })
                            clicked = true
                        }
                        else {
                            newRoot.innerHTML = ''
                        }
                    })
                }
                else {
                    let currentType = typeof data[d]
                    let el = document.createElement('li')
                    let display = null

                    switch (currentType) {
                        case 'object':
                            display = 'null'
                            break;
                        default:
                            display = data[d]
                            break;
                    }

                    let titleSpan = document.createElement('span')
                    let contentSpan = document.createElement('span')

                    titleSpan.innerText = `${d}: `
                    titleSpan.classList.add('titleStyle')

                    contentSpan.innerText = wrapTextWithDelimiters(display, maxLength);
                    contentSpan.classList.add(currentType)

                    el.appendChild(titleSpan)
                    el.appendChild(contentSpan)

                    root.appendChild(el)
                }
            }
        }
    </script>

    <div class="navbar">
        <div class="navbar-left">
            <div class="navbar-title">Wazuh Agent Configuration Result</div>
            <p>Agent: NAME_PLACEHOLDER (ID_PLACEHOLDER)</p>
            <p>Report Date: DATETIME_PLACEHOLDER</p>
        </div>
        <div class="navbar-links">
            <a href="#" onclick="expandAll()">Show All</a>
            <a href="#" onclick="collapseAll()">Hide All</a>
            <a href="#" onclick="window.print()">Print</a>
        </div>
    </div>

    <div class="content">
        <script>renderJson({data:JSON_PLACEHOLDER})</script>
    </div>

    <div class="footer">
        <p>Visit official Wazuh documentation for <a href="https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html" target="_blank">Local configuration (ossec.conf)</a>, <a href="https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html" target="_blank">Centralized configuration (agent.conf)</a> and <a href="https://documentation.wazuh.com/current/user-manual/reference/internal-options.html" target="_blank">Local internal options</a>.</p>
        <p>The results displayed on this page are consolidated configurations and may vary for each agent.</p>
        <p>&copy; 2025 <a href="https://zaferbalkan.com" target="_blank">Zafer Balkan</a></p>
        <p>The brand <a href="https://wazuh.com/" target="_blank">Wazuh</a> and related marks, emblems and images are registered trademarks of their respective owners.</p>
    </div>
</body>
</html>
"""

        return (
            template.replace("NAME_PLACEHOLDER", agent_name)
            .replace("ID_PLACEHOLDER", agent_id)
            .replace("DATETIME_PLACEHOLDER", dt.now(tz=timezone.utc).isoformat())
            .replace("JSON_PLACEHOLDER", json)
        )


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)  # type: ignore
        return super().default(o)


@dataclass
class FinalConf:
    content: dict

    def __init__(self, ossec_conf: dict, agent_conf: dict) -> None:
        c = ossec_conf.copy().get("ossec_config", {})
        a = agent_conf.copy().get("agent_config", {})

        if a:
            c = self._merge_dicts(c, a)

        self.content = c

    @classmethod
    def _merge_dicts(
        cls, current: dict, incoming: dict, skip_conditionals: bool = False
    ) -> dict:
        result = current.copy()
        for key, value in incoming.items():
            if skip_conditionals and key in ("@os", "@profile", "@name"):
                continue
            if key not in result:
                result[key] = value
            else:
                result[key] = cls._merge_value(key, result[key], value)
        return result

    @classmethod
    def _merge_value(cls, key: str, current: Any, incoming: Any) -> Any:
        if key == "localfile":
            return cls._merge_localfiles(current, incoming)

        if isinstance(current, dict) and isinstance(incoming, dict):
            return cls._merge_dicts(current, incoming)

        repeatable = {
            "directories",
            "ignore",
            "nodiff",
            "windows_registry",
            "registry_ignore",
            "policy",
        }
        if key in repeatable or isinstance(current, list) or isinstance(incoming, list):
            current_items = current if isinstance(current, list) else [current]
            incoming_items = incoming if isinstance(incoming, list) else [incoming]
            return current_items + incoming_items

        # Wazuh reads ossec.conf before agent.conf, so the later scalar wins.
        return incoming

    @staticmethod
    def _merge_localfiles(current: Any, incoming: Any) -> Any:
        current_items = current if isinstance(current, list) else [current]
        incoming_items = incoming if isinstance(incoming, list) else [incoming]
        result = list(current_items)

        for item in incoming_items:
            if isinstance(item, dict) and "location" in item:
                for index, existing in enumerate(result):
                    if (
                        isinstance(existing, dict)
                        and existing.get("location") == item["location"]
                    ):
                        result[index] = item
                        break
                else:
                    result.append(item)
            else:
                result.append(item)

        return result

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.content, cls=EnhancedJSONEncoder, indent=indent)


class ConfParser:
    __agent_os: str
    __agent_name: str
    __agent_id: str
    __agent_profile: list[str]
    __conf: FinalConf

    def __init__(
        self,
        ossec_conf_path: pathlib.Path | str | None = None,
        agent_conf_path: pathlib.Path | str | None = None,
        client_keys_path: pathlib.Path | str | None = None,
        local_internal_options_path: pathlib.Path | str | None = None,
    ) -> None:

        self.__agent_profile = []
        self.__get_agent_info(client_keys_path=client_keys_path)

        if ossec_conf_path is None:
            if os.name == "posix":
                ossec_conf_path = "/var/ossec/etc/ossec.conf"
            else:
                ossec_conf_path = "C:/Program Files (x86)/ossec-agent/ossec.conf"
            if os.path.exists(ossec_conf_path) is False:
                print(
                    f"Could not find ossec.conf file at {ossec_conf_path}. Please provide the correct path."
                )
                sys.exit(1)

        if agent_conf_path is None:
            if os.name == "posix":
                agent_conf_path = "/var/ossec/etc/shared/agent.conf"
            else:
                agent_conf_path = "C:/Program Files (x86)/ossec-agent/shared/agent.conf"
            if os.path.exists(agent_conf_path) is False:
                print(
                    f"Could not find agent.conf file at {agent_conf_path}. Please provide the correct path."
                )
                sys.exit(1)

        self.__conf = FinalConf(
            ossec_conf=self.__parse_conf(ossec_conf_path),
            agent_conf=self.__parse_conf(agent_conf_path),
        )

        # This is optional
        local_internal_options = self.__parse_local_internal_options(
            local_internal_options_path
        )
        if local_internal_options != {}:
            self.__conf.content["local_internal_options"] = local_internal_options

    def get_json(self, indent: int | None = 2) -> str:
        return self.__conf.to_json(indent=indent)

    def get_html(self) -> str:
        return HtmlGenerator().generate(
            self.__agent_name, self.__agent_id, self.__conf.to_json()
        )

    def __get_agent_info(
        self, client_keys_path: pathlib.Path | str | None = None
    ) -> None:
        # get OS info
        if os.name == "posix":
            self.__agent_os = "Linux"
        else:
            self.__agent_os = "Windows"

        # Get agent name and profile
        if client_keys_path is None:
            if os.name == "posix":
                client_keys_path = "/var/ossec/etc/client.keys"
            else:
                client_keys_path = "C:/Program Files (x86)/ossec-agent/client.keys"

        if os.path.exists(client_keys_path) is False:
            print(
                f"Could not find agent_info file at {client_keys_path}. Please provide the correct path."
            )
            sys.exit(1)

        with open(client_keys_path, "r", encoding="utf-8") as file:
            sections = file.read().split(" ")
            self.__agent_id = sections[0]
            self.__agent_name = sections[1]

    def __parse_conf(self, file_path: pathlib.Path | str) -> dict:
        with open(file_path, "r", encoding="utf-8") as file:
            text = file.read()

        text = self.__sanitize(text)

        content: dict = xmltodict.parse("<root>" + text + "</root>").get("root", {})

        # Get profile
        if content.get("ossec_config") is not None:
            if isinstance(content["ossec_config"], list) is False:
                content["ossec_config"] = [content["ossec_config"]]
            for section in content["ossec_config"]:
                if (
                    section.get("client") is not None
                    and section.get("client").get("config-profile") is not None
                ):
                    self.__agent_profile = (
                        str(section.get("client")["config-profile"])
                        .replace(" ", "")
                        .split(",")
                    )

        self.__deduplicate_blocks(content)

        content = OrderedDict(sorted(content.items()))
        return content

    def __parse_local_internal_options(
        self, file_path: pathlib.Path | str | None
    ) -> dict:
        # Get agent name and profile
        if file_path is None:
            if os.name == "posix":
                file_path = "/var/ossec/etc/local_internal_options.conf"
            else:
                file_path = (
                    "C:/Program Files (x86)/ossec-agent/local_internal_options.conf"
                )

        internal_options: dict[str, Any] = {}

        if os.path.exists(file_path):
            option_pattern = re.compile(r"(\w+).(\w+)\s*=\s*(\w+)")
            with open(file_path, "r", encoding="utf-8") as file:
                lines = file.readlines()

                for line in lines:
                    if line.startswith("#"):
                        continue
                    match = option_pattern.match(line)
                    if match:
                        module = match.group(1)
                        option = match.group(2)
                        value = match.group(3)

                        internal_options[module] = internal_options.get(module, {})
                        internal_options[module][option] = value
        return internal_options

    def __deduplicate_blocks(self, content: dict) -> None:
        if not content:
            return

        root_name, root_value = next(iter(content.items()))
        blocks = root_value if isinstance(root_value, list) else [root_value]
        blocks = [block for block in blocks if block is not None]

        merged: dict = {}
        for block in blocks:
            if root_name == "agent_config" and not self.__block_matches(block):
                continue
            merged = FinalConf._merge_dicts(
                merged, block, skip_conditionals=(root_name == "agent_config")
            )

        content[root_name] = merged

    def __block_matches(self, block: dict) -> bool:
        os_pattern = block.get("@os")
        if (
            os_pattern is not None
            and re.compile(os_pattern).match(self.__agent_os) is None
        ):
            return False

        profile_pattern = block.get("@profile")
        if profile_pattern is not None and not any(
            re.compile(profile_pattern).match(profile)
            for profile in self.__agent_profile
        ):
            return False

        name_pattern = block.get("@name")
        return not (
            name_pattern is not None
            and re.compile(name_pattern).match(self.__agent_name) is None
        )

    def __sanitize(self, xml_content: str) -> str:
        pattern = r"<query>(.*?)</query>"
        matches = re.findall(pattern, xml_content, re.DOTALL)

        for match in matches:
            extracted_data = match.strip()
            extracted_data = (
                extracted_data.replace("\\<", "<")
                .replace("\\>", ">")
                .replace(r"\t", " ")
                .replace(r"  ", " ")
            )
            extracted_data = re.sub(r"\n\s+", " ", extracted_data)
            xml_content = xml_content.replace(match, extracted_data)

        return xml_content


def is_admin() -> bool:
    if os.name == "posix":
        return int(os.getuid()) == 0  # type: ignore
    elif os.name == "nt":
        import ctypes

        # ``windll`` is only defined by ctypes on Windows, so accessing it via
        # getattr keeps cross-platform static analysis from treating it as a
        # universally available module attribute.
        return int(getattr(ctypes, "windll").shell32.IsUserAnAdmin()) != 0  # noqa: B009
    else:
        print("Unsupported OS")
        sys.exit(1)


def wazuh_agent_exists() -> bool:
    if os.name == "posix":
        return bool(os.path.exists("/var/ossec/bin/wazuh-agentd"))
    elif os.name == "nt":
        return bool(os.path.exists("C:/Program Files (x86)/ossec-agent"))
    else:
        print("Unsupported OS")
        sys.exit(1)


def main() -> None:
    arg_parser = argparse.ArgumentParser(
        prog="wresult",
        description="Parse the Wazuh agent running configuration, print to stdout as JSON or save to an HTML file.",
    )
    arg_parser.add_argument(
        "--agent_conf_path",
        "-ap",
        type=pathlib.Path,
        action="store",
        required=False,
        help=argparse.SUPPRESS,
    )
    arg_parser.add_argument(
        "--ossec_conf_path",
        "-op",
        type=pathlib.Path,
        action="store",
        required=False,
        help=argparse.SUPPRESS,
    )
    arg_parser.add_argument(
        "--client_keys_path",
        "-ck",
        type=pathlib.Path,
        action="store",
        required=False,
        help=argparse.SUPPRESS,
    )
    arg_parser.add_argument(
        "--local_internal_options_path",
        "-li",
        type=pathlib.Path,
        action="store",
        required=False,
        help=argparse.SUPPRESS,
    )
    arg_parser.add_argument(
        "--output",
        "-o",
        type=pathlib.Path,
        action="store",
        required=False,
        help="Output file path",
    )

    args = arg_parser.parse_args()

    # Parse ossec.conf file
    ossec_conf_path = args.ossec_conf_path

    # Parse agent.conf file
    agent_conf_path = args.agent_conf_path

    # Parse client.keys path for agent name and ID
    client_keys_path = args.client_keys_path

    # Parse local_internal_options file
    local_internal_options_path = args.local_internal_options_path

    if not ossec_conf_path or not agent_conf_path or not client_keys_path:
        # If not specified, it means the tool must read from default locations
        # This means we need to check for privileges.
        if not is_admin():
            print(
                "You need to run this script with higher privileges; either use sudo or run as an administrator."
            )
            sys.exit(1)

        if not wazuh_agent_exists():
            print("Wazuh agent is not installed on this machine.")
            sys.exit()

    policy_parser = ConfParser(
        ossec_conf_path=ossec_conf_path,
        agent_conf_path=agent_conf_path,
        client_keys_path=client_keys_path,
        local_internal_options_path=local_internal_options_path,
    )

    if args.output:
        # Save to file
        output_path: str = os.path.abspath(args.output)
        parent = os.path.dirname(output_path)
        if os.path.exists(parent) is False:
            print(
                f"Could not find the specified directory at {parent}. Please provide the correct path."
            )
            sys.exit(1)

        with open(output_path, "w", encoding="utf-8") as file:
            file.write(policy_parser.get_html())

    else:
        # Display extracted structure
        print(policy_parser.get_json())


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        print(f"Error: {e.args[0]}")
        try:
            sys.exit(1)
        except SystemExit:
            os._exit(1)
