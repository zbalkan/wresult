#!/usr/bin/env python3

import argparse
import dataclasses
import json
import os
import pathlib
import re
from dataclasses import dataclass
from typing import Optional, OrderedDict, Union

import xmltodict


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)  # type: ignore
        return super().default(o)


@dataclass
class Conf:
    content: dict

    def to_json(self, indent: Optional[int] = None) -> str:
        return json.dumps(self.content, cls=EnhancedJSONEncoder, indent=indent)


@dataclass
class FinalConf(Conf):

    def __init__(self, ossec_conf: Conf, agent_conf: Conf) -> None:
        self.content = ossec_conf.content.copy()
        self.content.update(agent_conf.content)
        # TODO: consolidate the two configurations


class Parser:

    def parse_conf(self, file_path: Union[pathlib.Path, str]) -> Conf:
        with open(file_path, "r", encoding="utf-8") as file:
            text = file.read()

        text = self.__sanitize(text)

        content: dict = xmltodict.parse(
            '<root>' + text + '</root>').get("root", {})

        self.__consolidate_config_items(content)

        content = OrderedDict(sorted(content.items()))
        return Conf(content=content)

    def __consolidate_config_items(self, content) -> None:
        root = list(content.items())[0]
        # root[1] is either ossec_config or agent_config
        if isinstance(root[1], list):
            new_content = root[1][0]  # get the first item
            for i, internal_dict in enumerate(root[1]):
                if i == 0:
                    continue
                for key, value in internal_dict.items():
                    if new_content.get(key) is None:
                        new_content[key] = value
                    else:
                        if not isinstance(new_content[key], list):
                            new_content[key] = [new_content[key]]
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


def main() -> None:
    arg_parser = argparse.ArgumentParser(
        prog='wresult', description="Parse Wazuh agent configuration, print to stdout or save to an HTML file.")
    arg_parser.add_argument('--agent_conf_path', '-ap', type=pathlib.Path,
                            action="store", required=False, help=argparse.SUPPRESS)
    arg_parser.add_argument('--ossec_conf_path', '-op', type=pathlib.Path,
                            action="store", required=False, help=argparse.SUPPRESS)
    arg_parser.add_argument('--output', '-o', type=pathlib.Path,
                            action="store", required=False, help="Output file path")

    args = arg_parser.parse_args()

    # Parse agent.conf file
    if args.agent_conf_path is None:
        if os.name == 'linux':
            agent_conf_path = '/var/ossec/etc/shared/agent.conf'
        else:
            agent_conf_path = 'C:/Program Files (x86)/ossec-agent/shared/agent.conf'
    else:
        agent_conf_path = str(args.agent_conf_path)

    # Parse ossec.conf file
    if args.ossec_conf_path is None:
        if os.name == 'linux':
            ossec_conf_path = '/var/ossec/etc/ossec.conf'
        else:
            ossec_conf_path = 'C:/Program Files (x86)/ossec-agent/ossec.conf'
    else:
        ossec_conf_path = str(args.ossec_conf_path)

    policy_parser = Parser()
    agent_conf = policy_parser.parse_conf(agent_conf_path)
    ossec_conf = policy_parser.parse_conf(ossec_conf_path)
    final = FinalConf(ossec_conf, agent_conf)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as file:
            file.write(final.to_json(indent=2))

    else:
        # Display extracted structure
        print(final.to_json(2))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        exit(1)
