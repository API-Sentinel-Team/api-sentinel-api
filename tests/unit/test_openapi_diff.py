from server.modules.api_inventory.openapi_diff import OpenAPIDiffAnalyzer


def test_openapi_diff_detects_breaking_changes():
    analyzer = OpenAPIDiffAnalyzer()

    base_spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string"},
                                            "email": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        }
                    }
                },
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "email": {"type": "string"},
                                        "name": {"type": "string"},
                                    },
                                    "required": ["email"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "created",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string"},
                                            "email": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                },
            }
        },
    }

    revision_spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "post": {
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {"name": "tenant", "in": "query", "required": True, "schema": {"type": "string"}}
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "email": {"type": "string"},
                                        "name": {"type": "string"},
                                        "role": {"type": "string"},
                                    },
                                    "required": ["email", "role"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "created",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            }
        },
    }

    diff = analyzer.compare(base_spec, revision_spec)
    change_ids = {item["id"] for item in diff["breaking_changes"]}

    assert diff["summary"]["total_breaking_changes"] >= 5
    assert "method_removed" in change_ids
    assert "security_requirement_added" in change_ids
    assert "required_parameter_added" in change_ids
    assert "request_required_property_added" in change_ids
    assert "response_property_removed" in change_ids

    assert any(
        "version" in recommendation.lower() or "compatibility" in recommendation.lower()
        for recommendation in diff["recommendations"]
    )
