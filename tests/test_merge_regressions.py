import json

from src.wresult import ConfParser


BASE_OSSEC = """
<ossec_config>
  <syscheck>
    <frequency>43200</frequency>
    <directories>/etc</directories>
    <directories>/usr/bin</directories>
  </syscheck>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
</ossec_config>
"""


def parse_config(tmp_path, monkeypatch, agent_conf: str) -> dict:
    ossec = tmp_path / "ossec.conf"
    agent = tmp_path / "agent.conf"
    client_keys = tmp_path / "client.keys"

    ossec.write_text(BASE_OSSEC, encoding="utf-8")
    agent.write_text(agent_conf, encoding="utf-8")
    client_keys.write_text("001 test-agent any key", encoding="utf-8")

    def fake_agent_info(self, client_keys_path=None):
        self._ConfParser__agent_os = "Linux"
        self._ConfParser__agent_name = "test-agent"
        self._ConfParser__agent_id = "001"

    monkeypatch.setattr(
        ConfParser, "_ConfParser__get_agent_info", fake_agent_info
    )

    parser = ConfParser(
        ossec_conf_path=ossec,
        agent_conf_path=agent,
        client_keys_path=client_keys,
        local_internal_options_path=tmp_path / "missing-options.conf",
    )
    return json.loads(parser.get_json())


def locations(config: dict) -> list[str]:
    localfiles = config["localfile"]
    if not isinstance(localfiles, list):
        localfiles = [localfiles]
    return [item["location"] for item in localfiles]


def test_single_non_matching_os_block_is_ignored(tmp_path, monkeypatch) -> None:
    config = parse_config(
        tmp_path,
        monkeypatch,
        """
<agent_config os="Windows">
  <syscheck><frequency>60</frequency></syscheck>
</agent_config>
""",
    )

    assert config["syscheck"]["frequency"] == "43200"


def test_first_non_matching_block_is_filtered(tmp_path, monkeypatch) -> None:
    config = parse_config(
        tmp_path,
        monkeypatch,
        """
<agent_config os="Windows">
  <syscheck><frequency>60</frequency></syscheck>
</agent_config>
<agent_config>
  <sca><enabled>yes</enabled></sca>
</agent_config>
""",
    )

    assert config["syscheck"]["frequency"] == "43200"
    assert config["sca"]["enabled"] == "yes"


def test_matching_blocks_accumulate_localfiles(tmp_path, monkeypatch) -> None:
    config = parse_config(
        tmp_path,
        monkeypatch,
        """
<agent_config>
  <localfile><log_format>syslog</log_format><location>a.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>b.log</location></localfile>
</agent_config>
<agent_config os="Linux">
  <localfile><log_format>syslog</log_format><location>c.log</location></localfile>
</agent_config>
""",
    )

    assert locations(config) == ["/var/log/auth.log", "a.log", "b.log", "c.log"]


def test_syscheck_directories_accumulate(tmp_path, monkeypatch) -> None:
    config = parse_config(
        tmp_path,
        monkeypatch,
        """
<agent_config>
  <syscheck><directories>/opt/app</directories></syscheck>
</agent_config>
""",
    )

    assert config["syscheck"]["directories"] == ["/etc", "/usr/bin", "/opt/app"]


def test_profile_block_without_configured_profile_is_skipped(
    tmp_path, monkeypatch
) -> None:
    config = parse_config(
        tmp_path,
        monkeypatch,
        """
<agent_config profile="ubuntu">
  <syscheck><frequency>60</frequency></syscheck>
</agent_config>
""",
    )

    assert config["syscheck"]["frequency"] == "43200"


def test_localfile_dict_and_list_shapes_do_not_corrupt_merge(
    tmp_path, monkeypatch
) -> None:
    config = parse_config(
        tmp_path,
        monkeypatch,
        """
<agent_config>
  <localfile><log_format>syslog</log_format><location>x.log</location></localfile>
  <localfile><log_format>syslog</log_format><location>y.log</location></localfile>
</agent_config>
""",
    )

    assert locations(config) == ["/var/log/auth.log", "x.log", "y.log"]


def test_nested_name_attribute_is_preserved(tmp_path, monkeypatch) -> None:
    config = parse_config(
        tmp_path,
        monkeypatch,
        """
<agent_config>
  <wodle name="command">
    <disabled>no</disabled>
  </wodle>
</agent_config>
""",
    )

    assert config["wodle"]["@name"] == "command"
    assert config["wodle"]["disabled"] == "no"


def test_single_localfiles_with_different_locations_accumulate(
        tmp_path, monkeypatch) -> None:
    config = parse_config(
        tmp_path,
        monkeypatch,
        """
<agent_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/agent.log</location>
  </localfile>
</agent_config>
""",
    )

    assert locations(config) == ["/var/log/auth.log", "/var/log/agent.log"]


def test_single_localfile_with_same_location_is_replaced(
        tmp_path, monkeypatch) -> None:
    config = parse_config(
        tmp_path,
        monkeypatch,
        """
<agent_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
</agent_config>
""",
    )

    assert config["localfile"] == [{
        "log_format": "json",
        "location": "/var/log/auth.log",
    }]
