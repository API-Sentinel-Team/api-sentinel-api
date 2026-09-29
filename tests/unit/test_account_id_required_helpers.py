import pytest
from pathlib import Path

from server.api.routers.audit_logs import log_action
from server.modules.integrations.burp_importer import BurpImporter
from server.modules.integrations.postman_importer import PostmanImporter
from server.modules.identity.auth_rotator import AuthRotator
from server.modules.source_code_analyzer.scanner import scan_directory
from server.modules.test_executor.execution_engine import ExecutionEngine
from server.modules.test_executor.result_aggregator import ResultAggregator
from server.modules.threat_engine.actor_tracker import ActorTracker
from server.modules.traffic_capture.sample_data_writer import SampleDataWriter
from server.modules.vulnerability_detector.store import create_or_merge_vulnerability

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.mark.asyncio
async def test_auth_rotator_returns_empty_without_account_id():
    rotator = AuthRotator()
    headers = await rotator.get_auth_headers(db=object(), account_id=None)
    assert headers == {}


def test_result_aggregator_requires_account_id():
    aggregator = ResultAggregator()
    with pytest.raises(ValueError, match="account_id"):
        aggregator._account_id_for({}, {})


@pytest.mark.asyncio
async def test_sample_data_writer_requires_account_id():
    writer = SampleDataWriter()
    with pytest.raises(ValueError, match="account_id"):
        await writer.save("ep-1", {}, {}, db=None, account_id=None)


@pytest.mark.asyncio
async def test_actor_tracker_requires_account_id():
    tracker = ActorTracker()
    with pytest.raises(ValueError, match="account_id"):
        await tracker.track_activity(source_ip="198.51.100.1", account_id=None)


@pytest.mark.asyncio
async def test_create_or_merge_vulnerability_requires_account_id():
    with pytest.raises(ValueError, match="account_id"):
        await create_or_merge_vulnerability(db=None, vulnerability_data={"template_id": "TEST"})


def test_postman_importer_requires_account_id():
    with pytest.raises(ValueError, match="account_id"):
        PostmanImporter.parse_collection({"item": []}, account_id=None)


def test_burp_importer_requires_account_id():
    with pytest.raises(ValueError, match="account_id"):
        BurpImporter.parse_xml("<items></items>", account_id=None)


def test_postman_importer_parse_from_file_requires_account_id():
    collection_path = FIXTURES_DIR / "postman_minimal_collection.json"
    with pytest.raises(ValueError, match="account_id"):
        PostmanImporter.parse_from_file(str(collection_path), account_id=None)


def test_source_code_scanner_requires_account_id():
    repo_path = FIXTURES_DIR / "source_repo"
    with pytest.raises(ValueError, match="account_id"):
        scan_directory(str(repo_path), account_id=None)


@pytest.mark.asyncio
async def test_execution_engine_requires_endpoint_account_id():
    engine = ExecutionEngine(db=object())

    with pytest.raises(ValueError, match="account_id"):
        await engine._build_initial_context({})


@pytest.mark.asyncio
async def test_audit_log_helper_requires_account_id(db_session):
    with pytest.raises(ValueError, match="account_id"):
        await log_action(db_session, action="TEST_EVENT", account_id=None)
