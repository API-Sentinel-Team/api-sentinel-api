import datetime
from types import SimpleNamespace

from server.modules.pentest.artifact_retention import (
    artifact_referenced_by_open_finding,
    retention_cutoff,
)


def test_retention_cutoff_is_timezone_preserving_and_positive():
    now = datetime.datetime(2026, 9, 27, tzinfo=datetime.timezone.utc)
    assert retention_cutoff(now=now, retention_days=30) == datetime.datetime(
        2026, 8, 28, tzinfo=datetime.timezone.utc
    )


def test_open_finding_reference_blocks_artifact_deletion_but_closed_does_not():
    artifact = SimpleNamespace(id="artifact-1")
    open_finding = SimpleNamespace(status="OPEN", evidence={"artifact_id": "artifact-1"})
    closed_finding = SimpleNamespace(status="CLOSED", evidence={"artifact_id": "artifact-1"})

    assert artifact_referenced_by_open_finding(artifact, [open_finding]) is True
    assert artifact_referenced_by_open_finding(artifact, [closed_finding]) is False
