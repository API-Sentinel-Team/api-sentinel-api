"""
Integration tests for InputValidator across API routes.

Tests verify that malicious inputs are rejected:
- SQL injection payloads
- XSS attempts (script tags, event handlers)
- Path traversal attempts
- Oversized collections (DoS prevention)
- Malformed UUIDs
- Invalid email formats
- Out-of-range integers
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
from server.api.main import app
from server.modules.validation.input_validator import ValidationError, InputValidator


@pytest.fixture
def client():
    """Test client for FastAPI app."""
    return TestClient(app)


class TestInputValidatorRejection:
    """Test InputValidator rejection of malicious inputs."""

    def test_sql_injection_in_category_parameter(self):
        """Verify SQL injection attempts in query parameters are rejected."""
        sql_injection = "CRITICAL' OR '1'='1"
        with pytest.raises(ValidationError):
            InputValidator.validate_string(
                sql_injection,
                "category",
                max_length=100,
                allow_empty=False
            )

    def test_xss_script_tag_rejection(self):
        """Verify <script> tags are rejected."""
        xss_payload = "<script>alert('xss')</script>"
        with pytest.raises(ValidationError):
            InputValidator.sanitize_html(xss_payload)

    def test_xss_event_handler_rejection(self):
        """Verify event handler injections are rejected."""
        xss_payload = "<img src=x onerror='alert(1)'>"
        with pytest.raises(ValidationError):
            InputValidator.sanitize_html(xss_payload)

    def test_xss_javascript_protocol_rejection(self):
        """Verify javascript: protocol is rejected."""
        xss_payload = "<a href='javascript:void(0)'>click</a>"
        with pytest.raises(ValidationError):
            InputValidator.sanitize_html(xss_payload)

    def test_path_traversal_double_dot(self):
        """Verify .. directory traversal is rejected."""
        path_traversal = "../../../etc/passwd"
        with pytest.raises(ValidationError):
            InputValidator.validate_path(path_traversal)

    def test_path_traversal_backslash(self):
        """Verify backslash path traversal is rejected."""
        path_traversal = "..\\..\\windows\\system32"
        with pytest.raises(ValidationError):
            InputValidator.validate_path(path_traversal)

    def test_path_traversal_multiple_slashes(self):
        """Verify multiple consecutive slashes are rejected."""
        path_traversal = "////etc/passwd"
        with pytest.raises(ValidationError):
            InputValidator.validate_path(path_traversal)

    def test_path_traversal_windows_reserved_names(self):
        """Verify Windows reserved names are rejected."""
        for reserved in ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"]:
            with pytest.raises(ValidationError):
                InputValidator.validate_path(reserved)

    def test_collection_size_limit_rejected(self):
        """Verify oversized collections are rejected (DoS prevention)."""
        large_collection = ["item" + str(i) for i in range(15000)]
        with pytest.raises(ValidationError):
            InputValidator.validate_collection_size(
                large_collection,
                "items",
                max_size=10000
            )

    def test_invalid_uuid_format_rejected(self):
        """Verify invalid UUID formats are rejected."""
        invalid_uuids = [
            "not-a-uuid",
            "12345678-90ab-cdef-ghij-klmnopqrstuv",  # Invalid characters
            "12345678-90ab-cdef-1234",  # Incomplete
            "12345678-90ab-cdef-1234-567890abcde",   # Wrong segment length
        ]
        for invalid_uuid in invalid_uuids:
            with pytest.raises(ValidationError):
                InputValidator.validate_uuid(invalid_uuid)

    def test_invalid_email_format_rejected(self):
        """Verify invalid email formats are rejected."""
        invalid_emails = [
            "not-an-email",
            "@example.com",
            "user@",
            "user @example.com",
            "user@.com",
            "user@example",
        ]
        for invalid_email in invalid_emails:
            with pytest.raises(ValidationError):
                InputValidator.validate_email(invalid_email)

    def test_integer_out_of_range_rejected(self):
        """Verify integers outside allowed ranges are rejected."""
        with pytest.raises(ValidationError):
            InputValidator.validate_integer(
                -1,
                "offset",
                min_value=0,
                max_value=1000000
            )
        with pytest.raises(ValidationError):
            InputValidator.validate_integer(
                10001,
                "limit",
                min_value=1,
                max_value=10000
            )

    def test_password_too_short_rejected(self):
        """Verify passwords shorter than 12 characters are rejected."""
        with pytest.raises(ValidationError):
            InputValidator.validate_password("Short1!")

    def test_password_missing_digit_rejected(self):
        """Verify passwords without digits are rejected."""
        with pytest.raises(ValidationError):
            InputValidator.validate_password("NoDigitPassword!")

    def test_password_missing_letter_rejected(self):
        """Verify passwords without letters are rejected."""
        with pytest.raises(ValidationError):
            InputValidator.validate_password("123456789012!")

    def test_password_missing_special_char_rejected(self):
        """Verify passwords without special characters are rejected."""
        with pytest.raises(ValidationError):
            InputValidator.validate_password("NoSpecialChar1")

    def test_string_exceeds_max_length_rejected(self):
        """Verify strings exceeding max length are rejected."""
        long_string = "a" * 5000
        with pytest.raises(ValidationError):
            InputValidator.validate_string(
                long_string,
                "description",
                max_length=4096
            )

    def test_json_depth_exceeds_limit_rejected(self):
        """Verify JSON with excessive nesting is rejected (stack overflow prevention)."""
        # Create deeply nested structure
        nested = {"level": 0}
        current = nested
        for i in range(30):
            current["next"] = {"level": i + 1}
            current = current["next"]

        is_valid = InputValidator.validate_json_depth(nested, max_depth=20)
        assert not is_valid, "Deeply nested JSON should be rejected"

    def test_html_entity_encoding_applied(self):
        """Verify HTML entity encoding is applied to unsafe characters."""
        unsafe_text = '<script>alert("xss")</script>'
        # First verify it's rejected as-is
        with pytest.raises(ValidationError):
            InputValidator.sanitize_html(unsafe_text)

        # Verify safe text gets encoded but not rejected
        safe_text = "Normal & safe text with < and >"
        encoded = InputValidator.sanitize_html(safe_text)
        assert "&amp;" in encoded
        assert "&lt;" in encoded
        assert "&gt;" in encoded

    def test_empty_string_rejected_when_not_allowed(self):
        """Verify empty strings are rejected when allow_empty=False."""
        with pytest.raises(ValidationError):
            InputValidator.validate_string(
                "",
                "field_name",
                allow_empty=False
            )

    def test_whitespace_only_string_rejected(self):
        """Verify strings with only whitespace are rejected."""
        with pytest.raises(ValidationError):
            InputValidator.validate_string(
                "   ",
                "field_name",
                allow_empty=False
            )


class TestValidInputAcceptance:
    """Test InputValidator acceptance of valid inputs."""

    def test_valid_email_accepted(self):
        """Verify valid emails are accepted."""
        valid_emails = [
            "user@example.com",
            "john.doe+tag@example.co.uk",
            "test_email-123@subdomain.example.com",
        ]
        for email in valid_emails:
            result = InputValidator.validate_email(email)
            assert result == email.lower()

    def test_valid_uuid_accepted(self):
        """Verify valid UUIDs are accepted."""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        result = InputValidator.validate_uuid(valid_uuid)
        assert result == valid_uuid.lower()

    def test_valid_integers_accepted(self):
        """Verify valid integers within range are accepted."""
        result = InputValidator.validate_integer(50, "limit", min_value=1, max_value=100)
        assert result == 50

    def test_valid_path_accepted(self):
        """Verify valid paths are accepted."""
        valid_paths = [
            "/uploads/documents/file.pdf",
            "relative/path/to/file.txt",
            "/home/user/Documents",
        ]
        for path in valid_paths:
            result = InputValidator.validate_path(path)
            assert result == path

    def test_valid_password_accepted(self):
        """Verify valid passwords are accepted."""
        valid_password = "SecurePass123!"
        result = InputValidator.validate_password(valid_password)
        assert result == valid_password

    def test_valid_collection_accepted(self):
        """Verify valid collections are accepted."""
        valid_collection = ["item1", "item2", "item3"]
        result = InputValidator.validate_collection_size(valid_collection, "items", max_size=100)
        assert result == valid_collection

    def test_valid_json_depth_accepted(self):
        """Verify JSON with acceptable depth is accepted."""
        nested = {"level": 0}
        current = nested
        for i in range(10):
            current["next"] = {"level": i + 1}
            current = current["next"]

        is_valid = InputValidator.validate_json_depth(nested, max_depth=20)
        assert is_valid, "Shallow JSON should be accepted"


class TestInputValidatorEdgeCases:
    """Test InputValidator edge cases."""

    def test_email_max_length_enforcement(self):
        """Verify email length limit (RFC 5321) is enforced."""
        # Valid email: 254 chars is the max
        long_email = "a" * 240 + "@example.com"
        result = InputValidator.validate_email(long_email)
        assert result == long_email.lower()

        # Too long: > 254 chars
        too_long = "a" * 250 + "@example.com"
        with pytest.raises(ValidationError):
            InputValidator.validate_email(too_long)

    def test_password_max_length_bcrypt_compat(self):
        """Verify password max length respects bcrypt 72-char limit."""
        # 72 chars is max for bcrypt
        max_password = "ValidPassword123!" * 4 + "!!"  # 66 chars, safe
        result = InputValidator.validate_password(max_password)
        assert result == max_password

        # > 72 chars should be rejected
        too_long = "ValidPassword123!" * 5  # 80 chars
        with pytest.raises(ValidationError):
            InputValidator.validate_password(too_long)

    def test_url_encoded_path_traversal_rejected(self):
        """Verify URL-encoded path traversal attempts are rejected."""
        # %2e%2e = ..
        url_encoded_traversal = "%2e%2e/etc/passwd"
        with pytest.raises(ValidationError):
            InputValidator.validate_path(url_encoded_traversal)

    def test_pattern_validation_respected(self):
        """Verify custom regex patterns are enforced."""
        # Pattern: alphanumeric only
        valid = InputValidator.validate_string(
            "abc123",
            "field",
            pattern=r"^[a-zA-Z0-9]+$"
        )
        assert valid == "abc123"

        # Invalid: contains special character
        with pytest.raises(ValidationError):
            InputValidator.validate_string(
                "abc-123",
                "field",
                pattern=r"^[a-zA-Z0-9]+$"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
