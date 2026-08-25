"""Unit tests for the encoded PowerShell command detection rule. No database required."""

from app.detections.rules.encoded_powershell import EncodedPowerShellDetectionRule

RULE = EncodedPowerShellDetectionRule()

ENCODED_BLOB = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"


def _event(event_factory, command_line, process_name="powershell.exe"):
    return event_factory(
        event_type="process_creation",
        process_name=process_name,
        command_line=command_line,
    )


def test_dash_enc_detected(event_factory):
    event = _event(event_factory, f"powershell.exe -enc {ENCODED_BLOB}")

    results = RULE.evaluate([event])

    assert len(results) == 1
    assert results[0].rule_id == "encoded_powershell_command"
    assert results[0].evidence["command_line"] == event.command_line
    assert results[0].related_event_ids == [event.id]


def test_dash_encodedcommand_detected(event_factory):
    event = _event(event_factory, f"powershell.exe -EncodedCommand {ENCODED_BLOB}")
    assert len(RULE.evaluate([event])) == 1


def test_mixed_case_detected(event_factory):
    event = _event(event_factory, f"PoWeRsHeLL.exe -EnC {ENCODED_BLOB}", process_name="PoWeRsHeLL.exe")
    assert len(RULE.evaluate([event])) == 1


def test_normal_powershell_no_detection(event_factory):
    event = _event(event_factory, r"powershell.exe -File C:\scripts\backup.ps1")
    assert RULE.evaluate([event]) == []


def test_does_not_trigger_on_word_powershell_alone(event_factory):
    event = _event(
        event_factory,
        "powershell.exe -Command Write-Host 'this text mentions encoding but no flag'",
    )
    assert RULE.evaluate([event]) == []


def test_similar_but_different_flag_is_not_matched(event_factory):
    # "-Encoding" starts with "-enc" but is a distinct, legitimate flag.
    event = _event(event_factory, "powershell.exe -Encoding utf8 -File script.ps1")
    assert RULE.evaluate([event]) == []


def test_non_powershell_process_ignored_even_with_enc_flag(event_factory):
    event = _event(event_factory, f"cmd.exe -enc {ENCODED_BLOB}", process_name="cmd.exe")
    assert RULE.evaluate([event]) == []


def test_missing_command_line_no_detection(event_factory):
    event = _event(event_factory, None)
    assert RULE.evaluate([event]) == []
