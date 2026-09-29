import pytest
from server.modules.auth.jwt_issuer import JWTIssuer, TokenExpiredError, InvalidTokenError

@pytest.mark.asyncio
async def test_create_and_verify_token():
    data = {
        "sub": "user-123",
        "email": "raj@test.com",
        "role": "admin",
        "account_id": "acc-001"
    }
    payload = JWTIssuer.create_access_token(data)
    decoded = await JWTIssuer.verify_token(payload)
    assert decoded["sub"] == "user-123"
    assert decoded["account_id"] == "acc-001"
    assert decoded["role"] == "admin"

@pytest.mark.asyncio
async def test_expired_token_rejected():
    data = {"sub": "user-123"}
    # Create token that expired 1 second ago
    token = JWTIssuer.create_access_token(data, expires_in=-1)
    with pytest.raises(TokenExpiredError):
        await JWTIssuer.verify_token(token)

@pytest.mark.asyncio
async def test_tampered_token_rejected():
    data = {"sub": "user-123"}
    token = JWTIssuer.create_access_token(data)
    tampered = token[:-5] + "XXXXX"
    with pytest.raises(InvalidTokenError):
        await JWTIssuer.verify_token(tampered)
