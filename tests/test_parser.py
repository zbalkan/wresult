import sys

import pytest

from src.wresult import ConfParser


@pytest.mark.skipif(sys.platform != "win32", reason="MUST run on Windows")
def test_conf_parser() -> None:
    ossec_conf_path = "tests/data/ossec.conf"
    agent_conf_path = "tests/data/agent.conf"
    client_keys_path = "tests/data/client.keys"
    local_internal_options_path = "tests/data/local_internal_options.conf"

    policy_parser = ConfParser(ossec_conf_path=ossec_conf_path,
                               agent_conf_path=agent_conf_path,
                               client_keys_path=client_keys_path,
                               local_internal_options_path=local_internal_options_path)

    actual = policy_parser.get_json()

    # Exercise the real Windows agent-info path, but assert effective-config
    # semantics instead of freezing the complete serialized configuration.
    import json

    config = json.loads(actual)

    assert config["client"]["config-profile"] == "windows, windows10"
    assert config["client_buffer"] == {
        "disabled": "no",
        "queue_size": "50000",
        "events_per_second": "1000",
    }

    locations = [entry["location"] for entry in config["localfile"]]
    assert "Application" in locations
    assert "Security" in locations
    assert r"%PROGRAMFILES(X86)%\ossec-agent\ossec.log" in locations
    assert len(locations) == len(set(locations))

    directories = config["syscheck"]["directories"]
    directory_paths = [entry["#text"] for entry in directories]
    assert "%WINDIR%" in directory_paths
    assert r"%WINDIR%\SysNative" in directory_paths
    assert r"%SYSTEMDRIVE%\Users\*\Downloads" in directory_paths
    assert "D:,E:,F:,G:,H:,I:,J:,K:,L:,M:,N:,O:,P:,Q:,R:,S:,T:,U:,V:,W:,X:,Y:,Z:" in directory_paths

    assert config["local_internal_options"]["windows"]["debug"] == "1"
