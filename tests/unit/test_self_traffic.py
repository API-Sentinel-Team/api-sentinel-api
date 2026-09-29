from server.modules.ingestion.self_traffic import is_self_traffic


def test_blank_host_console_paths_are_self():
    assert is_self_traffic("", "/api/stream/recent", self_hosts=set())
    assert is_self_traffic("unknown", "/api/sensors/", self_hosts=set())
    assert is_self_traffic(None, "/api/collections/", self_hosts=set())
    assert is_self_traffic("", "/login", self_hosts=set())


def test_blank_host_customer_and_harbor_paths_are_kept():
    assert not is_self_traffic("", "/v2/finspot/api-sentinel-frontend/blobs/{digest}", self_hosts=set())
    assert not is_self_traffic("unknown", "/service/token", self_hosts=set())
    assert not is_self_traffic("", "/robots.txt", self_hosts=set())


def test_excluded_host_drops_all_paths():
    hosts = {"sentinel.wecrew.in"}
    assert is_self_traffic("sentinel.wecrew.in", "/login", self_hosts=hosts)
    assert is_self_traffic("https://sentinel.wecrew.in", "/api/health/ready", self_hosts=hosts)
    assert not is_self_traffic("harbor.wecrew.in", "/v2/", self_hosts=hosts)
    assert not is_self_traffic("itsm.wecrew.in", "/api/tickets", self_hosts=hosts)


def test_named_host_keeps_other_apps_api_prefix():
    assert not is_self_traffic("itsm.wecrew.in", "/api/tickets", self_hosts={"sentinel.wecrew.in"})
