#!/usr/bin/env python3

import argparse
import dataclasses
import json
import os
import pathlib
import re
from dataclasses import dataclass
from datetime import datetime as dt
from typing import Optional, OrderedDict, Union

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
    <title>Wazuh Configuration Viewer</title>
    <style>
        :root {
            --bg: rgb(255, 255, 255);
            --titleStyle: rgb(0, 0, 0);
            --string: rgb(96, 96, 100);
            --number: rgb(119, 152, 229);
            --boolean: rgb(206, 142, 227);
            --function: rgb(109, 176, 137);
            --objectNull: rgb(176, 142, 109);
            --undefined: rgb(176, 142, 109);
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
            color: var(--titleStyle)
        }

        .content {
            flex: 1;
            background-color: rgb(180, 180, 180);
            max-width: 90%;
        }

        .string {
            color: var(--string);
        }

        .string::before,
        .string::after {
            content: '"';
            color: var(--string)
        }

        .number {
            color: var(--number);
        }

        .boolean {
            color: var(--boolean)
        }

        .function {
            color: var(--function)
        }

        .object {
            color: var(--objectNull)
        }

        .undefined {
            color: var(--undefined)
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
    </script>

    <script type="text/javascript">
        function renderJson({root = '', data, depth = 0} = {}) {
            const wordwrapPattern = /(?![^\\n]{1,120}$)([^\\n]{1,120})\\s/g;

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

                    contentSpan.innerText = display.replace(wordwrapPattern, '$1\\n');
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
            <div class="navbar-title">Wazuh Configuration Viewer</div>
            <p>Agent: NAME_PLACEHOLDER (ID_PLACEHOLDER)</p>
            <p>Report Date: DATETIME_PLACEHOLDER</p>
        </div>
        <div class="navbar-links">
            <a href="#" onclick="expandAll()" class="button">Show All</a>
            <a href="#" onclick="collapseAll()" class="button">Hide All</a>
        </div>
    </div>

    <div class="content">
        <script>renderJson({data:JSON_PLACEHOLDER})</script>
    </div>

    <div class="footer">
        <p>Visit official Wazuh documentation for <a href="https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html" target="_blank">Local configuration (ossec.conf)</a> and <a href="https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html" target="_blank">Centralized configuration (agent.conf)</a>. The results displayed on this page are consolidated configurations and may vary for each agent.</p>
        <p>&copy; 2025 <a href="https://zaferbalkan.com" target="_blank">Zafer Balkan</a></p>
        <p>The brand <a href="https://wazuh.com/" target="_blank">Wazuh</a> and related marks, emblems and images are registered trademarks of their respective owners.</p>
    </div>
</body>
</html>
"""

        return template.replace("NAME_PLACEHOLDER", agent_name).replace("ID_PLACEHOLDER", agent_id).replace("DATETIME_PLACEHOLDER", dt.now().isoformat()).replace("JSON_PLACEHOLDER", json)


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)  # type: ignore
        return super().default(o)


@dataclass
class FinalConf():

    content: dict

    def __init__(self, ossec_conf: dict, agent_conf: dict) -> None:

        c = ossec_conf.copy().get("ossec_config", {})
        a = agent_conf.copy().get("agent_config", {})

        for key, value in a.items():
            if c.get(key) is None:
                c[key] = value
            else:
                if isinstance(c[key], list):
                    if isinstance(value, list):
                        c[key].extend(value)
                    else:
                        c[key].append(value)
                elif isinstance(c[key], dict):
                    # Get to the child objects
                    c[key].update(value)
                else:
                    c[key] = [c[key], value]

        self.content = c

    def to_json(self, indent: Optional[int] = None) -> str:
        return json.dumps(self.content, cls=EnhancedJSONEncoder, indent=indent)


class ConfParser:

    __agent_os: str
    __agent_name: str
    __agent_id: str
    __agent_profile: list[str]
    __conf: FinalConf

    def __init__(self, ossec_conf_path: Union[pathlib.Path, str, None] = None, agent_conf_path: Union[pathlib.Path, str, None] = None, agent_info_path: Union[pathlib.Path, str, None] = None) -> None:

        self.__get_agent_info(agent_info_path=agent_info_path)

        if ossec_conf_path is None:
            if os.name == 'posix':
                ossec_conf_path = '/var/ossec/etc/ossec.conf'
            else:
                ossec_conf_path = 'C:/Program Files (x86)/ossec-agent/ossec.conf'

        if agent_conf_path is None:
            if os.name == 'posix':
                agent_conf_path = '/var/ossec/etc/shared/agent.conf'
            else:
                agent_conf_path = 'C:/Program Files (x86)/ossec-agent/shared/agent.conf'

        self.__conf = FinalConf(
            ossec_conf=self.__parse_conf(ossec_conf_path), agent_conf=self.__parse_conf(agent_conf_path))

    def get_json(self, indent: Optional[int] = 2) -> str:
        return self.__conf.to_json(indent=indent)

    def get_html(self) -> str:
        return HtmlGenerator().generate(self.__agent_name, self.__agent_id, self.__conf.to_json())

    def __get_agent_info(self, agent_info_path: Union[pathlib.Path, str, None] = None) -> None:
        # get OS info
        if os.name == 'posix':
            self.__agent_os = "Linux"
        else:
            self.__agent_os = "Windows"

        # Get agent name and profile
        if agent_info_path is None:
            if os.name == 'posix':
                agent_info_path = '/var/ossec/etc/.agent_info'
            else:
                agent_info_path = 'C:/Program Files (x86)/ossec-agent/.agent_info'

        with open(agent_info_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            self.__agent_name = lines[0].strip()
            self.__agent_id = lines[2].strip()
            self.__agent_profile = lines[3].replace(
                ' ', '').replace(r'\n', '').split(",")

    def __parse_conf(self, file_path: Union[pathlib.Path, str]) -> dict:
        with open(file_path, "r", encoding="utf-8") as file:
            text = file.read()

        text = self.__sanitize(text)

        content: dict = xmltodict.parse(
            '<root>' + text + '</root>').get("root", {})

        self.__deduplicate_blocks(content)

        content = OrderedDict(sorted(content.items()))
        return content

    def __deduplicate_blocks(self, content: dict) -> None:
        root = list(content.items())[0]
        # root[1] is either ossec_config or agent_config
        if isinstance(root[1], list):
            new_content = root[1][0]  # get the first item
            for i, internal_dict in enumerate(root[1]):
                if i == 0:
                    continue
                # Handle config per os, profile or name
                # https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html#options
                if internal_dict.get('@os') is not None:
                    if re.compile(internal_dict.get('@os')).match(self.__agent_os):
                        new_content.update(internal_dict)
                elif internal_dict.get('@profile') is not None:
                    if re.compile(internal_dict.get('@profile')).match(self.__agent_profile):
                        new_content.update(internal_dict)
                elif internal_dict.get('@name') is not None:
                    if re.compile(internal_dict.get('@name')).match(self.__agent_name):
                        new_content.update(internal_dict)
                else:
                    for key, value in internal_dict.items():
                        if new_content.get(key) is None:
                            new_content[key] = value
                        else:
                            if not isinstance(new_content[key], list):
                                new_content[key] = [new_content[key]]
                            if isinstance(value, list):
                                new_content[key].extend(value)
                            else:
                                new_content[key].append(value)

            content[root[0]] = new_content

    def __sanitize(self, xml_content: str) -> str:
        pattern = r'<query>(.*?)</query>'
        matches = re.findall(pattern, xml_content, re.DOTALL)

        for match in matches:
            extracted_data = match.strip()
            extracted_data = extracted_data.replace(
                "\\<", "<").replace("\\>", ">").replace(r"\t", " ").replace(r"  ", " ")
            extracted_data = re.sub(r'\n\s+', ' ', extracted_data)
            xml_content = xml_content.replace(match, extracted_data)

        return xml_content


def is_admin() -> bool:
    if os.name == 'posix':
        return int(os.getuid()) == 0  # type: ignore
    elif os.name == 'nt':
        import ctypes
        return int(ctypes.windll.shell32.IsUserAnAdmin()) != 0
    else:
        raise NotImplementedError


def main() -> None:

    if not is_admin():
        raise PermissionError("You need to run this script as an administrator.")

    arg_parser = argparse.ArgumentParser(
        prog='wresult', description="Parse the Wazuh agent running configuration, print to stdout as JSON or save to an HTML file.")
    arg_parser.add_argument('--agent_conf_path', '-ap', type=pathlib.Path,
                            action="store", required=False, help=argparse.SUPPRESS)
    arg_parser.add_argument('--ossec_conf_path', '-op', type=pathlib.Path,
                            action="store", required=False, help=argparse.SUPPRESS)
    arg_parser.add_argument('--agent_info_path', '-ai', type=pathlib.Path,
                            action="store", required=False, help=argparse.SUPPRESS)
    arg_parser.add_argument('--output', '-o', type=pathlib.Path,
                            action="store", required=False, help="Output file path")

    args = arg_parser.parse_args()

    # Parse ossec.conf file
    ossec_conf_path = args.ossec_conf_path

    # Parse agent.conf file
    agent_conf_path = args.agent_conf_path

    # Parse agent info file
    agent_info_path = args.agent_info_path

    policy_parser = ConfParser(ossec_conf_path=ossec_conf_path,
                               agent_conf_path=agent_conf_path,
                               agent_info_path=agent_info_path)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as file:
            file.write(policy_parser.get_html())

    else:
        # Display extracted structure
        print(policy_parser.get_json())


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        exit(1)
