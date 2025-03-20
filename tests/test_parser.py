from wresult.wresult import ConfParser


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

    expected = """{
  "client": {
    "server": {
      "address": "wazuh.domain.local",
      "port": "1514",
      "protocol": "tcp"
    },
    "config-profile": "windows, windows10",
    "crypto_method": "aes",
    "notify_time": "10",
    "time-reconnect": "60",
    "auto_restart": "yes",
    "enrollment": {
      "enabled": "yes",
      "manager_address": "wazuh.domain.local",
      "groups": "default-windows"
    },
    "force_reconnect_interval": "30m"
  },
  "client_buffer": {
    "disabled": "no",
    "queue_size": "50000",
    "events_per_second": "1000"
  },
  "localfile": [
    {
      "location": "Application",
      "log_format": "eventchannel"
    },
    {
      "location": "Security",
      "log_format": "eventchannel",
      "query": {
        "QueryList": {
          "Query": {
            "@Id": "0",
            "@Path": "Security",
            "Select": {
              "@Path": "Security",
              "#text": "*"
            },
            "Suppress": [
              {
                "@Path": "Security",
                "#text": "*[System[(EventID = 4656)]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID = 4658)]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID = 4660)]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID = 4663)]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID = 4670)]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID = 4690)]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID = 4703)]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID = 4907)]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID = 5145)]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID = 5152)]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID = 5156)]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID = 5157)]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID = 5447)]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID = 4659)]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=5140)]] and *[EventData[Data[@Name='AccessMask'] and Data='0x1']] and (*[EventData[Data[@Name='ShareName'] and Data='\\\\*\\C$']] and *[EventData[Data[@Name='IpAddress'] and Data='127.0.0.1']])"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=5140)]] and *[EventData[Data[@Name='AccessMask'] and Data='0x1']] and *[EventData[Data[@Name='ShareName'] and Data='\\\\*\\SYSVOL']]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4634)]] and *[EventData[(Data[@Name='TargetDomainName'] and Data='Window Manager')]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4634)]] and *[EventData[(Data[@Name='TargetDomainName'] and Data='Font Driver Host')]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4634)]] and *[EventData[(Data[@Name='TargetUserName'] and Data='ANONYMOUS LOGON')]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\\Windows\\System32\\svchost.exe'))]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\\Windows\\System32\\services.exe'))]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\\Windows\\System32\\SearchIndexer.exe'))]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\\Windows\\System32\\winlogon.exe'))]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\\Windows\\System32\\gpupdate.exe'))]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\\Windows\\System32\\MusNotification.exe'))]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\\Windows\\System32\\sdbinst.exe'))]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\\Windows\\System32\\LogonUI.exe'))]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\\Windows\\System32\\smss.exe'))]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\\Windows\\System32\\powercfg.exe'))]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\\Windows\\System32\\CompatTelRunner.exe'))]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4957)]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=7040)]] and *[EventData[(Data[@Name='param4'] and Data='TrustedInstaller')]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=7040)]] and *[EventData[(Data[@Name='param4'] and Data='BITS')]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4698 or EventID=4699 or EventID=4700 or EventID=4701 or EventID=4702)]] and (*[EventData[(Data[@Name='SubjectUserSid'] and Data='S-1-5-18')]])"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4698 or EventID=4699 or EventID=4700 or EventID=4701 or EventID=4702)]] and (*[EventData[(Data[@Name='SubjectUserSid'] and Data='S-1-5-19')]])"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4698 or EventID=4699 or EventID=4700 or EventID=4701 or EventID=4702)]] and (*[EventData[(Data[@Name='SubjectUserSid'] and Data='S-1-5-20')]])"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4673)]] and (*[EventData[(Data[@Name='ProcessName'] and Data='C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe')]])"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4673)]] and (*[EventData[(Data[@Name='ProcessName'] and Data='C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe')]])"
              },
              {
                "@Path": "Security",
                "#text": "*[System[(EventID=4673)]] and (*[EventData[(Data[@Name='ProcessName'] and Data='C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_1.24.25200.0_x64__8wekyb3d8bbwe\\WindowsPackageManagerServer.exe')]])"
              },
              {
                "@Path": "Security",
                "#text": "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)]] and *[EventData[(Data[@Name='LogonType'] and Data='5') or (Data[@Name='LogonType'] and Data='0')]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)]] and *[EventData[(Data[@Name='TargetUserName'] and Data='ANONYMOUS LOGON')]]"
              },
              {
                "@Path": "Security",
                "#text": "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)]] and *[EventData[(Data[@Name='TargetUserSID'] and Data='S-1-5-18')]]"
              }
            ]
          }
        }
      }
    },
    {
      "location": "System",
      "log_format": "eventchannel",
      "query": {
        "QueryList": {
          "Query": {
            "@Id": "0",
            "@Path": "System",
            "Select": {
              "@Path": "System",
              "#text": "*"
            },
            "Suppress": [
              {
                "@Path": "System",
                "#text": "*[System[(EventID=10016)]] and *[EventData[(Data[@Name='param4'] and Data='{D63B10C5-BB46-4990-A94F-E40B9D520160}' and Data[@Name='param5'] and Data='{9CA88EE3-ACB7-47C8-AFC4-AB702511C276}' and Data[@Name='param8'] and Data='S-1-5-18')]]"
              },
              {
                "@Path": "System",
                "#text": "*[System[(EventID=10016)]] and *[EventData[( Data[@Name='param4'] and Data='{260EB9DE-5CBE-4BFF-A99A-3710AF55BF1E}' and Data[@Name='param5'] and Data='{260EB9DE-5CBE-4BFF-A99A-3710AF55BF1E}')]]"
              },
              {
                "@Path": "System",
                "#text": "*[System[(EventID=10016)]] and *[EventData[(Data[@Name='param4'] and Data='{C2F03A33-21F5-47FA-B4BB-156362A2F239}' and Data[@Name='param5'] and Data='{316CDED5-E4AE-4B15-9113-7055D84DCC97}' and Data[@Name='param8'] and Data='S-1-5-19')]]"
              },
              {
                "@Path": "System",
                "#text": "*[System[(EventID=10016)]] and *[EventData[(Data[@Name='param4'] and Data='{6B3B8D23-FA8D-40B9-8DBD-B950333E2C52}' and Data[@Name='param5'] and Data='{4839DDB7-58C2-48F5-8283-E1D1807D0D7D}' and Data[@Name='param8'] and Data='S-1-5-19')]]"
              },
              {
                "@Path": "System",
                "#text": "*[System[Provider[@Name='Microsoft-Windows-Hyper-V-VmSwitch']]]"
              },
              {
                "@Path": "System",
                "#text": "*[System[Provider[@Name='Microsoft-Windows-Time-Service']]]"
              },
              {
                "@Path": "System",
                "#text": "*[System[Provider[@Name='Microsoft-Windows-DNS-Client']]]"
              },
              {
                "@Path": "System",
                "#text": "*[System[Provider[@Name='Netwtw10']]]"
              },
              {
                "@Path": "System",
                "#text": "*[System[Provider[@Name='e1dexpress']]]"
              },
              {
                "@Path": "System",
                "#text": "*[System[Provider[@Name='Intel-SST-OED']]]"
              },
              {
                "@Path": "System",
                "#text": "*[System[Provider[@Name='nhi']]]"
              },
              {
                "@Path": "System",
                "#text": "*[System[Provider[@Name='Service Control Manager']]] and *[EventData[(Data[@Name='param4'] and Data='BITS')]]"
              },
              {
                "@Path": "System",
                "#text": "*[System[(Provider[@Name='Microsoft-Windows-WindowsUpdateClient'] and EventID=44)]]"
              }
            ]
          }
        }
      }
    },
    {
      "location": "active-response\\active-responses.log",
      "log_format": "syslog"
    },
    {
      "location": "Microsoft-Windows-Windows Defender/Operational",
      "log_format": "eventchannel",
      "query": "Event[Sytem/EventID != 1150]",
      "only-future-events": "no"
    },
    {
      "location": "Microsoft-Windows-Sysmon/Operational",
      "log_format": "eventchannel",
      "only-future-events": "no",
      "query": {
        "QueryList": {
          "Query": {
            "@Id": "0",
            "@Path": "Microsoft-Windows-Sysmon/Operational",
            "Select": {
              "@Path": "Microsoft-Windows-Sysmon/Operational",
              "#text": "*"
            },
            "Suppress": [
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[EventData[Data[@Name='Image'] and Data='C:\\Windows\\System32\\svchost.exe' and Data[@Name='DestinationPort'] and Data='5985']]"
              },
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[EventData[(Data[@Name='User'] = 'NT AUTHORITY\\SYSTEM' or Data[@Name='User'] = 'NT AUTHORITY\\LOCAL SERVICE' or Data[@Name='User'] = 'NT AUTHORITY\\NETWORK SERVICE') and Data[@Name='DestinationPort'] = 53]]"
              },
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[EventData[(Data[@Name='User'] = 'NT AUTHORITY\\SYSTEM' or Data[@Name='User'] = 'NT AUTHORITY\\LOCAL SERVICE' or Data[@Name='User'] = 'NT AUTHORITY\\NETWORK SERVICE') and Data[@Name='DestinationPort'] = 67]]"
              },
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[EventData[(Data[@Name='User'] = 'NT AUTHORITY\\SYSTEM' or Data[@Name='User'] = 'NT AUTHORITY\\LOCAL SERVICE' or Data[@Name='User'] = 'NT AUTHORITY\\NETWORK SERVICE') and Data[@Name='DestinationPort'] = 68]]"
              },
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[EventData[(Data[@Name='User'] = 'NT AUTHORITY\\SYSTEM' or Data[@Name='User'] = 'NT AUTHORITY\\LOCAL SERVICE' or Data[@Name='User'] = 'NT AUTHORITY\\NETWORK SERVICE') and Data[@Name='DestinationPort'] = 88]]"
              },
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[EventData[(Data[@Name='User'] = 'NT AUTHORITY\\SYSTEM' or Data[@Name='User'] = 'NT AUTHORITY\\LOCAL SERVICE' or Data[@Name='User'] = 'NT AUTHORITY\\NETWORK SERVICE') and Data[@Name='DestinationPort'] = 123]]"
              },
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[EventData[(Data[@Name='User'] = 'NT AUTHORITY\\SYSTEM' or Data[@Name='User'] = 'NT AUTHORITY\\LOCAL SERVICE' or Data[@Name='User'] = 'NT AUTHORITY\\NETWORK SERVICE') and Data[@Name='DestinationPort'] = 135]]"
              },
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[EventData[(Data[@Name='User'] = 'NT AUTHORITY\\SYSTEM' or Data[@Name='User'] = 'NT AUTHORITY\\LOCAL SERVICE' or Data[@Name='User'] = 'NT AUTHORITY\\NETWORK SERVICE') and Data[@Name='DestinationPort'] = 137]]"
              },
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[EventData[(Data[@Name='User'] = 'NT AUTHORITY\\SYSTEM' or Data[@Name='User'] = 'NT AUTHORITY\\LOCAL SERVICE' or Data[@Name='User'] = 'NT AUTHORITY\\NETWORK SERVICE') and Data[@Name='DestinationPort'] = 138]]"
              },
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[EventData[(Data[@Name='User'] = 'NT AUTHORITY\\SYSTEM' or Data[@Name='User'] = 'NT AUTHORITY\\LOCAL SERVICE' or Data[@Name='User'] = 'NT AUTHORITY\\NETWORK SERVICE') and Data[@Name='DestinationPort'] = 139]]"
              },
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[EventData[(Data[@Name='User'] = 'NT AUTHORITY\\SYSTEM' or Data[@Name='User'] = 'NT AUTHORITY\\LOCAL SERVICE' or Data[@Name='User'] = 'NT AUTHORITY\\NETWORK SERVICE') and Data[@Name='DestinationPort'] = 389]]"
              },
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[EventData[(Data[@Name='User'] = 'NT AUTHORITY\\SYSTEM' or Data[@Name='User'] = 'NT AUTHORITY\\LOCAL SERVICE' or Data[@Name='User'] = 'NT AUTHORITY\\NETWORK SERVICE') and Data[@Name='DestinationPort'] = 445]]"
              },
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[EventData[(Data[@Name='User'] = 'NT AUTHORITY\\SYSTEM' or Data[@Name='User'] = 'NT AUTHORITY\\LOCAL SERVICE' or Data[@Name='User'] = 'NT AUTHORITY\\NETWORK SERVICE') and Data[@Name='DestinationPort'] = 546]]"
              },
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[EventData[(Data[@Name='User'] = 'NT AUTHORITY\\SYSTEM' or Data[@Name='User'] = 'NT AUTHORITY\\LOCAL SERVICE' or Data[@Name='User'] = 'NT AUTHORITY\\NETWORK SERVICE') and Data[@Name='DestinationPort'] = 547]]"
              },
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[EventData[(Data[@Name='User'] = 'NT AUTHORITY\\SYSTEM' or Data[@Name='User'] = 'NT AUTHORITY\\LOCAL SERVICE' or Data[@Name='User'] = 'NT AUTHORITY\\NETWORK SERVICE') and Data[@Name='DestinationPort'] = 5355]]"
              },
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[EventData[(Data[@Name='User'] = 'NT AUTHORITY\\SYSTEM' or Data[@Name='User'] = 'NT AUTHORITY\\LOCAL SERVICE' or Data[@Name='User'] = 'NT AUTHORITY\\NETWORK SERVICE') and Data[@Name='DestinationPort'] = 1900]]"
              },
              {
                "@Path": "Microsoft-Windows-Sysmon/Operational",
                "#text": "*[System[(EventID=10)]] and (*[EventData[Data[@Name='GrantedAccess'] and Data='0x1410']] and (*[EventData[Data[@Name='TargetImage'] and Data='C:\\Windows\\system32\\lsass.exe']] or*[EventData[Data[@Name='TargetImage'] and Data='C:\\Windows\\system32\\winlogon.exe']]))"
              }
            ]
          }
        }
      }
    },
    {
      "location": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
      "log_format": "eventchannel",
      "only-future-events": "no"
    },
    {
      "location": "Microsoft-Windows-PowerShell/Operational",
      "log_format": "eventchannel",
      "only-future-events": "no"
    },
    {
      "location": "PowerShellCore/Operational",
      "log_format": "eventchannel",
      "only-future-events": "no"
    },
    {
      "location": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
      "log_format": "eventchannel",
      "only-future-events": "no"
    },
    {
      "location": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
      "log_format": "eventchannel",
      "only-future-events": "no"
    },
    {
      "location": "Microsoft-Windows-Application-Experience/Program-Inventory",
      "log_format": "eventchannel",
      "only-future-events": "no"
    },
    {
      "location": "Microsoft-Windows-DNS-Client/Operational",
      "log_format": "eventchannel",
      "query": "Event[System/EventID=3008 and (EventData/Data[@Name=\\"QueryOptions\\"] != \\"140737488355328\\" and EventData/Data[@Name=\\"QueryResults\\"]!=\\"\\")]",
      "only-future-events": "no"
    },
    {
      "location": "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
      "log_format": "eventchannel",
      "only-future-events": "no"
    },
    {
      "location": "Microsoft-Windows-TaskScheduler/Operational",
      "log_format": "eventchannel",
      "only-future-events": "no"
    },
    {
      "location": "Microsoft-Windows-VHDMP/Operational",
      "log_format": "eventchannel",
      "only-future-events": "no"
    },
    {
      "location": "Microsoft-Windows-SMBServer/Operational",
      "log_format": "eventchannel",
      "only-future-events": "no"
    },
    {
      "location": "Microsoft-Windows-SMBServer/Connectivity",
      "log_format": "eventchannel",
      "only-future-events": "no"
    },
    {
      "location": "Microsoft-Windows-SMBClient/Operational",
      "log_format": "eventchannel",
      "only-future-events": "no"
    },
    {
      "location": "Microsoft-Windows-SmbClient/Connectivity",
      "log_format": "eventchannel",
      "only-future-events": "no"
    },
    {
      "location": "Microsoft-Windows-AppLocker/EXE and DLL",
      "log_format": "eventchannel",
      "only-future-events": "no",
      "query": "Event/System[EventID = 8003 or EventID = 8004]"
    },
    {
      "location": "Microsoft-Windows-AppLocker/MSI and Script",
      "log_format": "eventchannel",
      "only-future-events": "no",
      "query": "Event/System[EventID = 8006 or EventID = 8007]"
    },
    {
      "location": "Microsoft-Windows-AppLocker/Packaged app-Deployment",
      "log_format": "eventchannel",
      "only-future-events": "no",
      "query": "Event/System[EventID = 8024 or EventID = 8025]"
    },
    {
      "location": "Microsoft-Windows-AppLocker/Packaged app-Execution",
      "log_format": "eventchannel",
      "only-future-events": "no",
      "query": "Event/System[EventID = 8021 or EventID = 8022]"
    },
    {
      "location": "%WINDIR%\\Sysnative\\logfiles\\firewall\\*.log",
      "only-future-events": "no",
      "ignore": "ALLOW",
      "log_format": "syslog"
    },
    {
      "location": "%PROGRAMFILES(X86)%\\ossec-agent\\ossec.log",
      "only-future-events": "no",
      "restrict": "ERROR",
      "log_format": "syslog"
    }
  ],
  "rootcheck": {
    "disabled": "no",
    "windows_apps": "./shared/win_applications_rcl.txt",
    "windows_malware": "./shared/win_malware_rcl.txt"
  },
  "sca": {
    "enabled": "no",
    "scan_on_start": "yes",
    "interval": "12h",
    "skip_nfs": "yes"
  },
  "syscheck": {
    "disabled": "no",
    "frequency": "21600",
    "directories": [
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "@restrict": "regedit.exe$|system.ini$|win.ini$",
        "#text": "%WINDIR%"
      },
      {
        "@whodata": "yes",
        "@recursion_level": "0",
        "@restrict": "at.exe$|attrib.exe$|cacls.exe$|cmd.exe$|eventcreate.exe$|ftp.exe$|lsass.exe$|net.exe$|net1.exe$|netsh.exe$|reg.exe$|regedt32.exe|regsvr32.exe|runas.exe|sc.exe|schtasks.exe|sethc.exe|subst.exe$",
        "#text": "%WINDIR%\\SysNative"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "#text": "%WINDIR%\\SysNative\\drivers\\etc"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "@restrict": "WMIC.exe$",
        "#text": "%WINDIR%\\SysNative\\wbem"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "@restrict": "powershell.exe$",
        "#text": "%WINDIR%\\SysNative\\WindowsPowerShell\\v1.0"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "@restrict": "winrm.vbs$",
        "#text": "%WINDIR%\\SysNative"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "@restrict": "at.exe$|attrib.exe$|cacls.exe$|cmd.exe$|eventcreate.exe$|ftp.exe$|lsass.exe$|net.exe$|net1.exe$|netsh.exe$|reg.exe$|regedit.exe$|regedt32.exe$|regsvr32.exe$|runas.exe$|sc.exe$|schtasks.exe$|sethc.exe$|subst.exe$",
        "#text": "%WINDIR%\\System32"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "#text": "%WINDIR%\\System32\\drivers\\etc"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "@restrict": "WMIC.exe$",
        "#text": "%WINDIR%\\System32\\wbem"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "@restrict": "winrm.vbs$",
        "#text": "%WINDIR%\\System32"
      },
      {
        "@check_all": "yes",
        "@realtime": "yes",
        "#text": "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "#text": "D:,E:,F:,G:,H:,I:,J:,K:,L:,M:,N:,O:,P:,Q:,R:,S:,T:,U:,V:,W:,X:,Y:,Z:"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "@restrict": "autoexec.bat$|boot.ini$|config.sys",
        "#text": "%SYSTEMDRIVE%"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "@restrict": "userinit.exe$",
        "#text": "%WINDIR%\\System32"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "#text": "%SYSTEMDRIVE%\\Users\\*\\Downloads"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "@restrict": "pwsh.exe$",
        "#text": "%SYSTEMDRIVE%\\Program Files\\PowerShell\\7"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "@report_changes": "yes",
        "#text": "%SYSTEMDRIVE%\\Program Files\\PowerShell\\7"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "@report_changes": "yes",
        "#text": "%SYSTEMDRIVE%\\Users\\*\\Documents\\PowerShell"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "@restrict": "powershell.exe$",
        "#text": "%WINDIR%\\System32\\WindowsPowerShell\\v1.0"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "#text": "%WINDIR%\\System32\\WindowsPowerShell\\v1.0"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "@report_changes": "yes",
        "#text": "%SYSTEMDRIVE%\\Users\\*\\Documents\\WindowsPowerShell"
      },
      {
        "@check_all": "yes",
        "@whodata": "yes",
        "@recursion_level": "0",
        "#text": "%WINDIR%\\SysNative\\GroupPolicy"
      }
    ],
    "ignore": [
      "E:\\harmonybackup",
      "%SYSTEMDRIVE%\\programdata\\checkpoint\\identitycollector",
      "%SYSTEMDRIVE%\\programdata\\checkpoint\\dbstore",
      "%SYSTEMDRIVE%\\program files (x86)\\ossec-agent\\wazuh-agent.state",
      "%SYSTEMDRIVE%\\program files (x86)\\ossec-agent\\wazuh-logcollector.state",
      "%SYSTEMDRIVE%\\program files (x86)\\ossec-agent\\queue\\logcollector\\file_status.json",
      "%SYSTEMDRIVE%\\program files (x86)\\ossec-agent\\queue\\syscollector\\db\\local.db-journal",
      "%SYSTEMDRIVE%\\program files (x86)\\ossec-agent\\queue\\fim\\db\\fim.db-journal",
      "%SYSTEMDRIVE%\\program files (x86)\\ossec-agent\\rids\\sender_counter",
      ".wal$|.db-wal$|.db$",
      "%SYSTEMDRIVE%\\program files (x86)\\systemscheduler\\events",
      "%SYSTEMDRIVE%\\mk_agent\\alertfiles"
    ],
    "windows_registry": [
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters\\Rules"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Microsoft Defender"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\SHKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Classes\\Mscfile\\Shell\\Open\\Command"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Control.exe"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Classes\\Exefile\\Shell\\Runas\\Command\\IsolatedCommand"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows Nt\\CurrentVersion\\Imagefileexecutionoptions"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Enum\\USBTor"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Enum\\USB"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Environment"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Control Panel\\Desktop\\Scrnsave.exe"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Command Processor\\Autorun"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\Desktop\\Components"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\Explorer Bars"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\Extensions"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\UrlSearchHooks\\Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Winlogon"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Run"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop\\Scrnsave.exe"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Explorer Bars"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Extensions"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Winlogon"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\System"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Taskman"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\GroupPolicy\\Scripts\\Shutdown"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\GroupPolicy\\Scripts\\Startup"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Shell"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logon"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System\\Scripts\\Shutdown"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System\\Scripts\\Startup"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Command\\Processor\\Autorun"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Explorer Bars"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Extensions"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Toolbar"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\LSA"
      },
      {
        "@arch": "both",
        "#text": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout"
      },
      {
        "@arch": "both",
        "#text": "HKEY_CURRENT_USER\\Keyboard Layout\\Preload"
      }
    ],
    "registry_ignore": [
      "HKEY_LOCAL_MACHINE\\Security\\Policy\\Secrets",
      "HKEY_LOCAL_MACHINE\\Security\\SAM\\Domains\\Account\\Users",
      {
        "@type": "sregex",
        "#text": "\\Enum$"
      },
      "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\MpsSvc\\Parameters\\AppCs",
      "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\MpsSvc\\Parameters\\PortKeywords\\DHCP",
      "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\MpsSvc\\Parameters\\PortKeywords\\IPTLSIn",
      "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\MpsSvc\\Parameters\\PortKeywords\\IPTLSOut",
      "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\MpsSvc\\Parameters\\PortKeywords\\RPC-EPMap",
      "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\MpsSvc\\Parameters\\PortKeywords\\Teredo",
      "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\PolicyAgent\\Parameters\\Cache",
      "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
      "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\ADOVMPPackage\\Final"
    ],
    "windows_audit_interval": "60",
    "process_priority": "10",
    "max_eps": "100",
    "synchronization": {
      "max_eps": "20"
    },
    "scan_on_start": "yes",
    "file_limit": {
      "enabled": "yes",
      "entries": "200000"
    },
    "registry_limit": {
      "enabled": "yes",
      "entries": "500000",
      "diff_size_limit": "100MB"
    }
  },
  "wodle": [
    {
      "@name": "syscollector",
      "disabled": "no",
      "interval": "1h",
      "scan_on_start": "yes",
      "hardware": "yes",
      "os": "yes",
      "network": "yes",
      "packages": "yes",
      "ports": {
        "@all": "no",
        "#text": "yes"
      },
      "processes": "yes",
      "synchronization": {
        "max_eps": "10"
      }
    },
    {
      "@name": "cis-cat",
      "disabled": "yes",
      "timeout": "1800",
      "interval": "1d",
      "scan-on-start": "yes",
      "java_path": "\\\\server\\jre\\bin\\java.exe",
      "ciscat_path": "C:\\cis-cat"
    },
    {
      "@name": "osquery",
      "disabled": "yes",
      "run_daemon": "yes",
      "bin_path": "C:\\Program Files\\osquery\\osqueryd",
      "log_path": "C:\\Program Files\\osquery\\log\\osqueryd.results.log",
      "config_path": "C:\\Program Files\\osquery\\osquery.conf",
      "add_labels": "yes"
    }
  ],
  "active-response": {
    "disabled": "no",
    "ca_store": "wpk_root.pem",
    "ca_verification": "yes"
  },
  "logging": {
    "log_format": "plain,json"
  },
  "global": {
    "jsonout_output": "yes",
    "alerts_log": "yes",
    "logall": "no",
    "logall_json": "no",
    "email_maxperhour": "12",
    "agents_disconnection_time": "10m",
    "agents_disconnection_alert_time": "0"
  },
  "local_internal_options": {
    "windows": {
      "debug": "1"
    }
  }
}"""

    actual = actual.replace('\\\\', '\\')
    assert actual == expected
