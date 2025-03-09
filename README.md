# Wazuh Configuration Parser

## Overview

This Python script parses Wazuh agent configuration files, specifically `merged.mg` and `ossec.conf`, to extract and format their contents into structured JSON output.

## Prerequisites

Ensure you have Python 3 installed along with the following dependencies:

```bash
pip install xmltodict
```

## Usage

Run the script from the command line:

```bash
python3 script.py --merged_mg_path /path/to/merged.mg --ossec_conf_path /path/to/ossec.conf --output result.json
```

### Arguments

- `--merged_mg_path` (`-mp`): Path to the `merged.mg` file (default: Wazuh's standard path)
- `--ossec_conf_path` (`-op`): Path to the `ossec.conf` file (default: Wazuh's standard path)
- `--output` (`-o`): Path to save the JSON output file

## Example Output

```json
{
  "ar_section": ["some configuration data"],
  "agent_config": [{"key": "value"}],
  "sca_files": {
    "some_rcl.txt": ["check1", "check2"]
  },
  "ossec_conf": {
    "config_section": {"setting": "value"}
  }
}
```

## Error Handling

- Ensures the `merged.mg` file starts with `#default`
- Validates section presence before parsing
- Uses `xmltodict` to safely parse XML with error handling

## License

This project is open-source and licensed under the MIT License.
