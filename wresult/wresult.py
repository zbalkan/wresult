#!/usr/bin/env python3

import argparse
import dataclasses
import json
import os
import pathlib
import re
from dataclasses import dataclass
from typing import Any, Optional, Union

import xmltodict


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)  # type: ignore
        return super().default(o)


@dataclass
class MergedMg:
    ar_section: list[str]
    agent_config: list[dict]
    sca_files: list[str]

    def to_json(self, indent: Optional[int] = None) -> str:
        return json.dumps(self, cls=EnhancedJSONEncoder, indent=indent)


class Parser:
    def parse_merged_mg(self, file_path: Union[pathlib.Path, str]) -> MergedMg:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()

        # Validate first line
        lines = content.split("\n")
        if not lines[0].startswith("#default"):
            raise ValueError(
                "Invalid file format: First line must start with '#default'")

        # Find the start of AR section
        ar_index: int = 0
        agent_index: int = 0
        sca_index: int = 0
        for i, line in enumerate(lines):
            if re.match(r"!\d+ ar.conf", line):
                ar_index = i
            elif re.match(r"!\d+ agent.conf", line):
                agent_index = i
            elif re.match(r"!\d+ .*?rcl.txt", line):
                if sca_index == 0:
                    sca_index = i  # Use only the first match.
                    break
            else:
                continue

        if ar_index == 0 or agent_index == 0 or sca_index == 0:
            raise ValueError("Invalid file format: Missing section")

        ar_section = lines[ar_index + 1:agent_index]

        # Parse agent.conf XML using xmltodict
        agent_config_list: list[dict[str, Any]] = []
        agent_config_text = '\n'.join(lines[agent_index + 1:sca_index])
        try:
            agent_config_list = list(xmltodict.parse(
                "<root>" + agent_config_text + "</root>").get("root", []).values())
            if agent_config_list == [None]:
                agent_config_list = []
        except Exception:
            agent_config_list = []

        agent_config = agent_config_list  # type: ignore

        # Parse SCA files into a dictionary
        sca_files_list = []
        for i in range(sca_index, len(lines)):
            line = lines[i]
            if line.startswith("!"):
                m = re.match(r"!\d+ (.*?rcl.txt)", line)
                if m:
                    sca_files_list.append(m.group(1))

        sca_files = sca_files_list

        return MergedMg(
            ar_section=ar_section,
            agent_config=agent_config,
            sca_files=sca_files
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog='wresult', description="Parse Wazuh agent configuration, print to stdout or save to an HTML file.")
    parser.add_argument('--merged_mg_path', '-mp', type=pathlib.Path, action="store", required=False,
                        help=argparse.SUPPRESS)
    parser.add_argument('--ossec_conf_path', '-op', type=pathlib.Path, action="store", required=False,
                        help=argparse.SUPPRESS)
    parser.add_argument('--output', '-o', type=pathlib.Path, action="store", required=False,
                        help="Output file path")

    args = parser.parse_args()
    if args.merged_mg_path is None:
        if os.name == 'linux':
            merged_mg_path = pathlib.Path(
                '/var/ossec/etc/shared/merged.mg')
        else:
            merged_mg_path = pathlib.Path(
                'C:/Program Files (x86)/ossec-agent/shared/merged.mg')
    else:
        merged_mg_path = str(args.merged_mg_path)

    # Parse merged.mg file

    parser = Parser()
    merged_mg = parser.parse_merged_mg(merged_mg_path)

    # Display extracted structure
    print(merged_mg.to_json(indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        exit(1)
