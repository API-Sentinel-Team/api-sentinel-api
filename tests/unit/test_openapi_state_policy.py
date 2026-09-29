from server.modules.pentest.openapi_state_policy import apply_openapi_state_policy


def test_openapi_state_policy_filters_state_changing_operations_in_safe_mode():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "parameters": [{"name": "tenant", "in": "header"}],
                "get": {"operationId": "listUsers"},
                "post": {"operationId": "createUser", "summary": "Create user"},
            },
            "/users/{id}": {
                "delete": {"operationId": "deleteUser"},
            },
        },
    }

    filtered, metadata = apply_openapi_state_policy(spec, allow_state_change=False)

    assert filtered["paths"] == {
        "/users": {
            "parameters": [{"name": "tenant", "in": "header"}],
            "get": {"operationId": "listUsers"},
        }
    }
    assert metadata["filtered"] is True
    assert metadata["input_operation_count"] == 3
    assert metadata["retained_operation_count"] == 1
    assert metadata["blocked_operation_count"] == 2
    assert metadata["destructive_operation_count"] == 2
    assert metadata["blocked_destructive_operation_count"] == 2
    assert metadata["destructive_methods"] == ["DELETE", "PATCH", "POST", "PUT"]
    assert metadata["blocked_destructive_operations"] == [
        {"method": "POST", "path": "/users", "operation_id": "createUser", "summary": "Create user"},
        {"method": "DELETE", "path": "/users/{id}", "operation_id": "deleteUser"},
    ]
    assert metadata["blocked_operations"] == [
        {"method": "POST", "path": "/users", "operation_id": "createUser", "summary": "Create user"},
        {"method": "DELETE", "path": "/users/{id}", "operation_id": "deleteUser"},
    ]


def test_openapi_state_policy_retains_all_operations_when_state_change_allowed():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "get": {"operationId": "listUsers"},
                "post": {"operationId": "createUser"},
            },
        },
    }

    filtered, metadata = apply_openapi_state_policy(
        spec,
        allow_state_change=True,
        allow_destructive_methods=True,
    )

    assert filtered == spec
    assert metadata["filtered"] is False
    assert metadata["input_operation_count"] == 2
    assert metadata["retained_operation_count"] == 2
    assert metadata["blocked_operation_count"] == 0
    assert metadata["destructive_operation_count"] == 1
    assert metadata["blocked_destructive_operation_count"] == 0
    assert metadata["blocked_destructive_operations"] == []


def test_openapi_state_policy_reports_retained_destructive_operations_when_explicitly_allowed():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users/{id}": {
                "delete": {"operationId": "deleteUser"},
                "patch": {"operationId": "patchUser"},
            },
        },
    }

    filtered, metadata = apply_openapi_state_policy(
        spec,
        allow_state_change=True,
        allow_destructive_methods=True,
    )

    assert filtered == spec
    assert metadata["filtered"] is False
    assert metadata["allow_destructive_methods"] is True
    assert metadata["input_operation_count"] == 2
    assert metadata["retained_operation_count"] == 2
    assert metadata["blocked_operation_count"] == 0
    assert metadata["destructive_operation_count"] == 2
    assert metadata["blocked_destructive_operation_count"] == 0
    assert metadata["blocked_destructive_operations"] == []


def test_openapi_state_policy_requires_explicit_destructive_method_opt_in():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "post": {"operationId": "createUser"},
            },
            "/users/{id}": {
                "delete": {"operationId": "deleteUser"},
                "patch": {"operationId": "patchUser"},
            },
        },
    }

    filtered, metadata = apply_openapi_state_policy(spec, allow_state_change=True)

    assert filtered["paths"] == {}
    assert metadata["filtered"] is True
    assert metadata["allow_state_change"] is True
    assert metadata["allow_destructive_methods"] is False
    assert metadata["retained_operation_count"] == 0
    assert metadata["blocked_operation_count"] == 3
    assert metadata["blocked_destructive_operation_count"] == 3
    assert metadata["blocked_destructive_operations"] == [
        {"method": "POST", "path": "/users", "operation_id": "createUser"},
        {"method": "DELETE", "path": "/users/{id}", "operation_id": "deleteUser"},
        {"method": "PATCH", "path": "/users/{id}", "operation_id": "patchUser"},
    ]


def test_openapi_state_policy_redacts_blocked_operation_evidence():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users?token=raw-token": {
                "post": {
                    "operationId": "createUser token=raw-operation-token",
                    "summary": "Create user with password=raw-password",
                },
            },
        },
    }

    _filtered, metadata = apply_openapi_state_policy(spec, allow_state_change=False)

    assert metadata["blocked_operations"] == [
        {
            "method": "POST",
            "path": "/users?token=****",
            "operation_id": "createUser token=****",
            "summary": "Create user with password=****",
        }
    ]
    assert "raw-token" not in str(metadata)
    assert "raw-operation-token" not in str(metadata)
    assert "raw-password" not in str(metadata)
