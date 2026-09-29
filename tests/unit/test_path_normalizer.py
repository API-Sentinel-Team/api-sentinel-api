from server.modules.api_inventory.endpoint_discovery import inventory_path
from server.modules.api_inventory.path_normalizer import PathNormalizer


def test_normalize_collapses_oci_blob_digest():
    normalizer = PathNormalizer()
    path = (
        "/v2/finspot/api-sentinel-frontend/blobs/"
        "sha256:61ca4f733c802afd9e05a32f0de0361b6d713b8b53292dc15fb093229f648674"
    )
    assert normalizer.normalize(path) == "/v2/finspot/api-sentinel-frontend/blobs/{digest}"


def test_normalize_collapses_bare_sha256_segment():
    normalizer = PathNormalizer()
    digest = "d7e5070240863957ebb0b5a44a5729963c3462666baa2947d00628cb5f2d5773"
    assert normalizer.normalize(f"/objects/{digest}") == "/objects/{sha256}"


def test_inventory_path_strips_query_and_rejects_attack_chars():
    assert inventory_path("/api/users?id=1") == "/api/users"
    assert inventory_path("/admin/<script>") is None
    assert inventory_path("/static/../etc/passwd") is None
