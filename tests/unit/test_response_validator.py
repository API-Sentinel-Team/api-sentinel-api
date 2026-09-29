import pytest
from server.modules.test_executor.response_validator import ResponseValidator

def test_status_code_validation_pass():
    validator = ResponseValidator()
    response = {"status_code": 200, "body": '{"data": "secret"}'}
    rules = {"response_code": {"eq": 200}}
    # In our implementation, validate returns True if rules match (i.e. vuln found)
    assert validator.validate(response, rules) is True

def test_body_contains_check():
    validator = ResponseValidator()
    response = {"body": "root:x:0:0"}
    rules = {"response_payload": {"contains": ["root:"]}}
    assert validator.validate(response, rules) is True

def test_status_code_mismatch():
    validator = ResponseValidator()
    response = {"status_code": 404}
    rules = {"response_code": {"eq": 200}}
    assert validator.validate(response, rules) is False
