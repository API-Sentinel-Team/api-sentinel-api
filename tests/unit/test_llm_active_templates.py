from server.config import settings
from server.modules.test_executor.yaml_parser import YAMLParser


def test_active_llm_security_templates_are_runnable_and_context_tagged():
    templates = {
        template["id"]: template
        for template in YAMLParser(settings.TESTS_LIBRARY_PATH).load_all_templates()
        if str(template.get("id", "")).startswith("LLM_")
    }

    expected = {
        "LLM_PROMPT_INJECTION_SYSTEM_PROMPT_LEAKAGE",
        "LLM_RAG_CONTEXT_EXFILTRATION",
        "LLM_INDIRECT_PROMPT_INJECTION",
        "LLM_DANGEROUS_TOOL_INVOCATION",
        "LLM_PRIVILEGE_ESCALATING_TOOL_INVOCATION",
    }
    assert expected <= set(templates)

    for template_id in expected:
        template = templates[template_id]
        assert template["security_category"] == "llm"
        assert template["execute"]["type"] == "single"
        assert template["execute"]["allow_state_change"] is False
        assert template["execute"]["max_active_requests_per_test"] == 1
        assert template["api_selection_filters"]["method"]["eq"] == "POST"
        assert template["validate"]["response_code"]["lt"] <= 500


def test_active_llm_security_templates_declare_deterministic_evidence_contracts():
    templates = {
        template["id"]: template
        for template in YAMLParser(settings.TESTS_LIBRARY_PATH).load_all_templates()
        if str(template.get("id", "")).startswith("LLM_")
    }

    expected_required = {
        "LLM_PROMPT_INJECTION_SYSTEM_PROMPT_LEAKAGE": [
            "body_content_persisted",
            "matched_text_persisted",
            "request_body_sha256",
            "response_body_sha256",
            "signal_count",
            "signal_types",
        ],
        "LLM_RAG_CONTEXT_EXFILTRATION": [
            "body_content_persisted",
            "matched_text_persisted",
            "request_body_sha256",
            "response_body_sha256",
            "signal_count",
            "signal_types",
            "retrieval_context_sha256",
            "retrieval_context_surface_keys",
        ],
        "LLM_INDIRECT_PROMPT_INJECTION": [
            "body_content_persisted",
            "matched_text_persisted",
            "request_body_sha256",
            "response_body_sha256",
            "signal_count",
            "signal_types",
            "untrusted_context_sha256",
            "untrusted_context_surface_keys",
        ],
        "LLM_DANGEROUS_TOOL_INVOCATION": [
            "body_content_persisted",
            "matched_text_persisted",
            "request_body_sha256",
            "response_body_sha256",
            "signal_count",
            "signal_types",
            "tool_invocation_sha256",
            "tool_invocation_surface_keys",
        ],
        "LLM_PRIVILEGE_ESCALATING_TOOL_INVOCATION": [
            "body_content_persisted",
            "matched_text_persisted",
            "request_body_sha256",
            "response_body_sha256",
            "signal_count",
            "signal_types",
            "tool_invocation_sha256",
            "tool_invocation_surface_keys",
        ],
    }

    for template_id, required in expected_required.items():
        metadata = templates[template_id]["active_llm"]["deterministic_evidence"]
        assert metadata["validator"] == "deterministic_active_llm_signal_judge"
        assert metadata["required"] == required
        assert metadata["body_content_persisted"] is False
        assert metadata["matched_text_persisted"] is False
        assert metadata["promotion_decision"] == "promote_unconfirmed_finding"
