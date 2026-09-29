import pytest
from server.modules.test_executor.selection_filter import SelectionFilterEngine

def test_method_filter_matches_correctly():
    engine = SelectionFilterEngine()
    template = {
        "api_selection_filters": {
            "method": {"eq": "GET"}
        }
    }
    endpoint = {"method": "GET", "path": "/api/users/123"}
    should_run, _ = engine.should_run(template, endpoint)
    assert should_run is True

def test_wrong_method_filtered_out():
    engine = SelectionFilterEngine()
    template = {
        "api_selection_filters": {
            "method": {"eq": "GET"}
        }
    }
    endpoint = {"method": "DELETE", "path": "/api/users/123"}
    should_run, _ = engine.should_run(template, endpoint)
    assert should_run is False


def test_evaluate_returns_stable_skip_reason_for_method_filter():
    engine = SelectionFilterEngine()
    template = {
        "api_selection_filters": {
            "method": {"eq": "GET"}
        }
    }

    decision = engine.evaluate(template, {"method": "DELETE", "path": "/api/users/123"})

    assert decision.should_run is False
    assert decision.extracted == {}
    assert decision.reason == "method_filter_mismatch"

def test_url_extraction():
    engine = SelectionFilterEngine()
    template = {
        "api_selection_filters": {
            "url": {"extract": "urlVar"}
        }
    }
    endpoint = {"url": "http://example.com/api/v1"}
    should_run, extracted = engine.should_run(template, endpoint)
    assert should_run is True
    assert extracted["urlVar"] == "http://example.com/api/v1"


def test_template_root_auth_requirement_skips_unauthenticated_endpoint():
    engine = SelectionFilterEngine()
    template = {
        "auth": {"authenticated": True},
        "api_selection_filters": {"method": {"eq": "GET"}},
    }

    should_run, _ = engine.should_run(template, {"method": "GET", "auth_types_found": []})

    assert should_run is False


def test_evaluate_returns_stable_skip_reason_for_auth_context():
    engine = SelectionFilterEngine()
    template = {
        "auth": {"authenticated": True},
        "api_selection_filters": {"method": {"eq": "GET"}},
    }

    decision = engine.evaluate(template, {"method": "GET", "auth_types_found": []})

    assert decision.should_run is False
    assert decision.reason == "requires_authenticated_endpoint"


def test_template_root_auth_requirement_allows_observed_auth_context():
    engine = SelectionFilterEngine()
    template = {
        "auth": {"authenticated": True},
        "api_selection_filters": {"method": {"eq": "GET"}},
    }

    should_run, _ = engine.should_run(template, {"method": "GET", "auth_types_found": ["bearer"]})

    assert should_run is True


def test_template_unauthenticated_requirement_skips_authenticated_endpoint():
    engine = SelectionFilterEngine()
    template = {"auth": {"authenticated": False}}

    should_run, _ = engine.should_run(template, {"auth_types_found": ["cookie"]})

    assert should_run is False


def test_bfla_include_roles_requires_configured_role_context():
    engine = SelectionFilterEngine()
    template = {
        "api_selection_filters": {
            "include_roles_access": {"param": "ADMIN"},
        }
    }

    should_run_without_roles, _ = engine.should_run(template, {}, roles_context={})
    should_run_with_roles, _ = engine.should_run(template, {}, roles_context={"ADMIN": "Bearer admin"})

    assert should_run_without_roles is False
    assert should_run_with_roles is True


def test_bfla_include_roles_accepts_template_list_style():
    engine = SelectionFilterEngine()
    template = {
        "api_selection_filters": {
            "include_roles_access": ["MEMBER", "VIEWER"],
        }
    }

    should_run_without_roles, _ = engine.should_run(template, {}, roles_context={"ADMIN": "Bearer admin"})
    should_run_with_roles, _ = engine.should_run(template, {}, roles_context={"VIEWER": "Bearer viewer"})

    assert should_run_without_roles is False
    assert should_run_with_roles is True


def test_bfla_exclude_roles_accepts_template_list_style():
    engine = SelectionFilterEngine()
    template = {
        "api_selection_filters": {
            "exclude_roles_access": ["ADMIN"],
        }
    }

    should_skip_with_excluded_role, _ = engine.should_run(template, {}, roles_context={"ADMIN": "Bearer admin"})
    should_run_without_excluded_role, _ = engine.should_run(template, {}, roles_context={"MEMBER": "Bearer member"})

    assert should_skip_with_excluded_role is False
    assert should_run_without_excluded_role is True


def test_evaluate_returns_stable_skip_reason_for_missing_role_context():
    engine = SelectionFilterEngine()
    template = {
        "api_selection_filters": {
            "include_roles_access": {"param": "ADMIN"},
        }
    }

    decision = engine.evaluate(template, {}, roles_context={})

    assert decision.should_run is False
    assert decision.reason == "required_role_context_missing"


def test_bfla_exclude_roles_blocks_disallowed_role_context():
    engine = SelectionFilterEngine()
    template = {
        "api_selection_filters": {
            "exclude_roles_access": {"param": "MEMBER"},
        }
    }

    should_run, _ = engine.should_run(template, {}, roles_context={"MEMBER": "Bearer member"})

    assert should_run is False


def test_private_variable_context_extracts_request_body_identifier():
    engine = SelectionFilterEngine()
    template = {
        "api_selection_filters": {
            "private_variable_context": {"gt": 0, "extract": "private_var"}
        }
    }
    endpoint = {
        "private_variable_count": 1,
        "last_request_body": '{"user_id": "user-123", "token": "raw-token"}',
    }

    should_run, extracted = engine.should_run(template, endpoint)

    assert should_run is True
    assert extracted["private_var"] == {
        "key": "user_id",
        "value": "user-123",
        "source": "request_body",
    }


def test_private_variable_context_extracts_query_identifier_without_secret():
    engine = SelectionFilterEngine()
    template = {
        "api_selection_filters": {
            "private_variable_context": {"gt": 0, "extract": "private_var"}
        }
    }
    endpoint = {
        "private_variable_count": 1,
        "last_query_string": "token=raw-token&account_id=acct-123",
    }

    should_run, extracted = engine.should_run(template, endpoint)

    assert should_run is True
    assert extracted["private_var"]["key"] == "account_id"
    assert extracted["private_var"]["value"] == "acct-123"


def test_private_variable_context_requires_extractable_identifier_when_template_needs_it():
    engine = SelectionFilterEngine()
    template = {
        "api_selection_filters": {
            "private_variable_context": {"gt": 0, "extract": "private_var"}
        }
    }
    endpoint = {"private_variable_count": 1}

    should_run, extracted = engine.should_run(template, endpoint)

    assert should_run is False
    assert extracted == {}


def test_response_payload_filter_accepts_list_style_for_one_rules():
    engine = SelectionFilterEngine()
    template = {
        "api_selection_filters": {
            "response_payload": [
                {
                    "for_one": {
                        "key": {"regex": "admin|superuser|system"},
                        "value": {"eq": False},
                    }
                }
            ]
        }
    }

    should_run, _ = engine.should_run(
        template,
        {"last_response_body": '{"is_admin": false}'},
    )
    should_skip, _ = engine.should_run(
        template,
        {"last_response_body": "{}"},
    )

    assert should_run is True
    assert should_skip is False


def test_evaluate_returns_stable_skip_reason_for_missing_private_context():
    engine = SelectionFilterEngine()
    template = {
        "api_selection_filters": {
            "private_variable_context": {"gt": 0, "extract": "private_var"}
        }
    }

    decision = engine.evaluate(template, {"private_variable_count": 1})

    assert decision.should_run is False
    assert decision.reason == "private_variable_context_missing"


def test_context_aware_selection_summary_reports_required_available_and_missing_signals_without_secrets():
    engine = SelectionFilterEngine()
    templates = [
        {
            "auth": {"authenticated": True},
            "api_selection_filters": {
                "endpoint_in_traffic_context": True,
                "private_variable_context": {"gt": 0},
                "include_roles_access": {"param": "ADMIN"},
                "param_context": {"param": "user_id", "extract": "user_context"},
                "request_payload": {"for_one": {"key": {"regex": "user_id"}}},
                "response_payload": {"contains": ["ok"]},
                "response_headers": {
                    "for_one": {"key": {"eq": "set-cookie"}, "value": {"contains": "session"}}
                },
                "response_code": {"gte": 200, "lt": 300},
                "method": {"eq": "GET"},
                "url": {"extract": "urlVar"},
            },
        },
        {
            "api_selection_filters": {
                "exclude_roles_access": {"param": "GUEST"},
            },
        },
    ]
    endpoints = [
        {
            "method": "GET",
            "url": "https://api.example.test/users/123?account_id=acct-123",
            "path": "/users/123",
            "last_response_code": 200,
            "last_request_body": '{"user_id": "user-123", "password": "raw-password"}',
            "last_response_body": '{"status": "ok", "account_id": "acct-123"}',
            "last_response_headers": {
                "Set-Cookie": "session=raw-cookie",
                "Authorization": "Bearer raw-token",
            },
            "auth_types_found": ["bearer"],
            "private_variable_count": 2,
        }
    ]

    summary = engine.summarize_context_aware_selection(
        templates,
        endpoints,
        roles_context={"ADMIN": "Bearer role-token"},
    )

    expected_signals = [
        "auth_context",
        "traffic_context",
        "private_variable_context",
        "role_context",
        "param_context",
        "payload_context",
        "header_context",
        "response_code_context",
        "method_context",
        "url_context",
    ]
    assert summary["context_aware_selection"] is True
    assert summary["required_signals"] == expected_signals
    assert summary["available_signals"] == expected_signals
    assert summary["satisfied_signals"] == expected_signals
    assert summary["missing_signals"] == []
    assert summary["template_count"] == 2
    assert summary["endpoint_count"] == 1
    assert summary["required_signal_counts"]["role_context"] == 2
    assert summary["available_signal_counts"]["auth_context"] == 1
    assert summary["available_signal_counts"]["role_context"] == 1

    rendered_summary = repr(summary)
    for secret_or_payload_value in (
        "raw-password",
        "raw-cookie",
        "raw-token",
        "role-token",
        "user-123",
        "acct-123",
    ):
        assert secret_or_payload_value not in rendered_summary


def test_context_aware_selection_summary_is_not_ready_when_required_signals_have_no_evidence():
    engine = SelectionFilterEngine()
    templates = [
        {
            "auth": {"authenticated": True},
            "api_selection_filters": {
                "endpoint_in_traffic_context": True,
                "private_variable_context": {"gt": 0},
            },
        }
    ]

    summary = engine.summarize_context_aware_selection(templates, endpoints=[])

    assert summary["context_aware_selection"] is False
    assert summary["required_signals"] == [
        "auth_context",
        "traffic_context",
        "private_variable_context",
    ]
    assert summary["available_signals"] == []
    assert summary["satisfied_signals"] == []
    assert summary["missing_signals"] == [
        "auth_context",
        "traffic_context",
        "private_variable_context",
    ]
    assert summary["available_signal_counts"]["auth_context"] == 0


def test_context_aware_selection_summary_is_not_ready_with_partial_signal_evidence():
    engine = SelectionFilterEngine()
    templates = [
        {
            "id": "private-context-token=raw-template-token",
            "auth": {"authenticated": True},
            "api_selection_filters": {
                "method": {"eq": "GET"},
                "url": {"extract": "urlVar"},
                "endpoint_in_traffic_context": True,
                "private_variable_context": {"gt": 0},
            },
        }
    ]
    endpoints = [
        {
            "method": "GET",
            "url": "https://api.example.test/users",
            "auth_types_found": ["bearer"],
        }
    ]

    summary = engine.summarize_context_aware_selection(templates, endpoints=endpoints)

    assert summary["context_aware_selection"] is False
    assert summary["satisfied_signals"] == [
        "auth_context",
        "method_context",
        "url_context",
    ]
    assert summary["missing_signals"] == [
        "traffic_context",
        "private_variable_context",
    ]
    assert summary["satisfied_signal_count"] == 3
    assert summary["missing_signal_count"] == 2
    assert summary["context_signal_gaps"] == [
        {
            "signal": "traffic_context",
            "required_template_count": 1,
            "available_context_count": 0,
            "affected_template_count": 1,
            "affected_template_ids": ["private-context-token=****"],
            "recommended_inputs": [
                "ingest request or response samples for target endpoints",
            ],
        },
        {
            "signal": "private_variable_context",
            "required_template_count": 1,
            "available_context_count": 0,
            "affected_template_count": 1,
            "affected_template_ids": ["private-context-token=****"],
            "recommended_inputs": [
                "capture non-secret object identifiers from path, query, request body, or response body",
            ],
        },
    ]

    rendered_summary = repr(summary)
    assert "raw-template-token" not in rendered_summary
    assert "https://api.example.test/users" not in rendered_summary


def test_context_aware_selection_summary_reports_redacted_selection_outcomes():
    engine = SelectionFilterEngine()
    templates = [
        {
            "id": "needs-traffic",
            "api_selection_filters": {
                "method": {"eq": "GET"},
                "endpoint_in_traffic_context": True,
            },
        },
        {
            "id": "delete-only",
            "api_selection_filters": {
                "method": {"eq": "DELETE"},
            },
        },
    ]
    endpoints = [
        {
            "method": "GET",
            "path": "/users/123",
            "last_request_body": '{"token": "raw-token", "account_id": "acct-123"}',
        },
        {
            "method": "GET",
            "path": "/users/456",
        },
    ]

    summary = engine.summarize_context_aware_selection(templates, endpoints=endpoints)

    assert summary["selection_outcomes"] == {
        "template_endpoint_pair_count": 4,
        "selected_pair_count": 1,
        "skipped_pair_count": 3,
        "selected_template_count": 1,
        "selected_endpoint_count": 1,
        "skip_reason_counts": {
            "endpoint_traffic_context_missing": 1,
            "method_filter_mismatch": 2,
        },
        "selection_starved": False,
        "starved_template_count": 1,
        "starved_templates": [
            {
                "template_index": 1,
                "template_id": "delete-only",
                "security_category": "uncategorized",
                "required_signals": ["method_context"],
                "selected_endpoint_count": 0,
                "skipped_endpoint_count": 2,
                "skip_reason_counts": {"method_filter_mismatch": 2},
            },
        ],
        "starved_template_report_truncated": False,
        "security_category_coverage": [
            {
                "security_category": "uncategorized",
                "template_count": 2,
                "selected_template_count": 1,
                "starved_template_count": 1,
                "selected_pair_count": 1,
                "skipped_pair_count": 3,
                "coverage_status": "covered",
                "skip_reason_counts": {
                    "endpoint_traffic_context_missing": 1,
                    "method_filter_mismatch": 2,
                },
            },
        ],
        "security_category_coverage_gap_count": 0,
        "security_category_coverage_gaps": [],
        "security_category_coverage_report_truncated": False,
        "pair_decisions": [
            {
                "template_index": 0,
                "template_id": "needs-traffic",
                "endpoint_index": 0,
                "endpoint_id": "endpoint_0",
                "security_category": "uncategorized",
                "selected": True,
                "reason": "selected",
                "extracted_variable_names": [],
            },
            {
                "template_index": 0,
                "template_id": "needs-traffic",
                "endpoint_index": 1,
                "endpoint_id": "endpoint_1",
                "security_category": "uncategorized",
                "selected": False,
                "reason": "endpoint_traffic_context_missing",
                "extracted_variable_names": [],
            },
            {
                "template_index": 1,
                "template_id": "delete-only",
                "endpoint_index": 0,
                "endpoint_id": "endpoint_0",
                "security_category": "uncategorized",
                "selected": False,
                "reason": "method_filter_mismatch",
                "extracted_variable_names": [],
            },
            {
                "template_index": 1,
                "template_id": "delete-only",
                "endpoint_index": 1,
                "endpoint_id": "endpoint_1",
                "security_category": "uncategorized",
                "selected": False,
                "reason": "method_filter_mismatch",
                "extracted_variable_names": [],
            },
        ],
        "pair_decision_count": 4,
        "pair_decision_report_truncated": False,
    }
    rendered_summary = repr(summary)
    assert "raw-token" not in rendered_summary
    assert "acct-123" not in rendered_summary
    assert "/users/123" not in rendered_summary


def test_context_aware_selection_summary_reports_starved_templates_without_endpoint_secrets():
    engine = SelectionFilterEngine()
    templates = [
        {
            "id": "needs-private-token=raw-template-token",
            "api_selection_filters": {
                "private_variable_context": {"gt": 0, "extract": "private_var"},
            },
        },
        {
            "id": "delete-only",
            "api_selection_filters": {
                "method": {"eq": "DELETE"},
            },
        },
        {
            "id": "auth-ready",
            "auth": {"authenticated": True},
        },
    ]
    endpoints = [
        {
            "method": "GET",
            "path": "/accounts/12345?token=raw-endpoint-token",
            "url": "https://api.example.test/accounts/12345?token=raw-endpoint-token",
            "auth_types_found": ["bearer"],
        },
    ]

    summary = engine.summarize_context_aware_selection(templates, endpoints=endpoints)

    assert summary["selection_outcomes"]["starved_template_count"] == 2
    assert summary["selection_outcomes"]["starved_templates"] == [
        {
            "template_index": 0,
            "template_id": "needs-private-token=****",
            "security_category": "uncategorized",
            "required_signals": ["private_variable_context"],
            "selected_endpoint_count": 0,
            "skipped_endpoint_count": 1,
            "skip_reason_counts": {"private_variable_context_missing": 1},
        },
        {
            "template_index": 1,
            "template_id": "delete-only",
            "security_category": "uncategorized",
            "required_signals": ["method_context"],
            "selected_endpoint_count": 0,
            "skipped_endpoint_count": 1,
            "skip_reason_counts": {"method_filter_mismatch": 1},
        },
    ]
    rendered_summary = repr(summary)
    assert "raw-template-token" not in rendered_summary
    assert "raw-endpoint-token" not in rendered_summary
    assert "/accounts/12345" not in rendered_summary


def test_context_aware_selection_summary_reports_category_coverage_gaps_without_secrets():
    engine = SelectionFilterEngine()
    templates = [
        {
            "id": "authz-token=raw-template-token",
            "security_category": "authorization",
            "api_selection_filters": {
                "private_variable_context": {"gt": 0, "extract": "private_var"},
            },
        },
        {
            "id": "sql-injection",
            "info": {"tags": ["injection", "api"]},
            "api_selection_filters": {
                "method": {"eq": "POST"},
            },
        },
        {
            "id": "inventory-ready",
            "security_category": "inventory",
            "api_selection_filters": {
                "method": {"eq": "GET"},
            },
        },
    ]
    endpoints = [
        {
            "method": "GET",
            "path": "/accounts/12345?token=raw-endpoint-token",
            "url": "https://api.example.test/accounts/12345?token=raw-endpoint-token",
        },
    ]

    summary = engine.summarize_context_aware_selection(templates, endpoints=endpoints)

    outcomes = summary["selection_outcomes"]
    assert outcomes["security_category_coverage_gap_count"] == 2
    assert outcomes["security_category_coverage_gaps"] == [
        {
            "security_category": "authorization",
            "template_count": 1,
            "selected_template_count": 0,
            "starved_template_count": 1,
            "selected_pair_count": 0,
            "skipped_pair_count": 1,
            "coverage_status": "gap",
            "skip_reason_counts": {"private_variable_context_missing": 1},
        },
        {
            "security_category": "injection",
            "template_count": 1,
            "selected_template_count": 0,
            "starved_template_count": 1,
            "selected_pair_count": 0,
            "skipped_pair_count": 1,
            "coverage_status": "gap",
            "skip_reason_counts": {"method_filter_mismatch": 1},
        },
    ]
    assert outcomes["security_category_coverage"] == [
        *outcomes["security_category_coverage_gaps"],
        {
            "security_category": "inventory",
            "template_count": 1,
            "selected_template_count": 1,
            "starved_template_count": 0,
            "selected_pair_count": 1,
            "skipped_pair_count": 0,
            "coverage_status": "covered",
            "skip_reason_counts": {},
        },
    ]
    rendered_summary = repr(summary)
    assert "raw-template-token" not in rendered_summary
    assert "raw-endpoint-token" not in rendered_summary
    assert "/accounts/12345" not in rendered_summary


def test_context_aware_selection_reports_historical_finding_reason_without_finding_secrets():
    engine = SelectionFilterEngine()
    templates = [
        {
            "id": "authz-regression",
            "security_category": "authorization",
            "api_selection_filters": {
                "method": {"eq": "GET"},
                "historical_finding_context": {"category": "authorization"},
            },
        }
    ]
    endpoints = [
        {
            "id": "account-endpoint",
            "method": "GET",
            "path": "/accounts/12345",
            "finding_history": [
                {
                    "category": "authorization",
                    "title": "BOLA leaked account raw-secret-account-12345",
                    "severity": "HIGH",
                }
            ],
        }
    ]

    summary = engine.summarize_context_aware_selection(templates, endpoints=endpoints)

    assert "historical_finding_context" in summary["required_signals"]
    assert "historical_finding_context" in summary["available_signals"]
    assert summary["selection_outcomes"]["pair_decisions"] == [
        {
            "template_index": 0,
            "template_id": "authz-regression",
            "endpoint_index": 0,
            "endpoint_id": "account-endpoint",
            "security_category": "authorization",
            "selected": True,
            "reason": "Selected because this endpoint has prior authorization findings.",
            "extracted_variable_names": [],
        }
    ]

    rendered_summary = repr(summary)
    assert "raw-secret-account-12345" not in rendered_summary
    assert "/accounts/12345" not in rendered_summary


def test_response_payload_filter_handles_null_last_response_body():
    """Endpoints imported from an OpenAPI spec have last_response_body = None.

    The key is present but null, so dict.get(key, "") returns None rather than
    the default, and the payload filter must not blow up on it.
    """
    engine = SelectionFilterEngine()
    template = {
        "api_selection_filters": {
            "response_payload": {"contains": ["password"]}
        }
    }
    endpoint = {"method": "GET", "path": "/api/users", "last_response_body": None}

    decision = engine.evaluate(template, endpoint)

    assert decision.should_run is False
    assert decision.reason == "response_payload_filter_mismatch"


def test_response_payload_not_contains_matches_when_body_is_null():
    engine = SelectionFilterEngine()
    template = {
        "api_selection_filters": {
            "response_payload": {"not_contains": ["secret"]}
        }
    }
    endpoint = {"method": "GET", "path": "/api/users", "last_response_body": None}

    decision = engine.evaluate(template, endpoint)

    assert decision.should_run is True
