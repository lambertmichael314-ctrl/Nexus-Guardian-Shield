from core.security import get_password_hash, verify_password, create_access_token

def test_password_hashing():
    password = "SuperSecretPassword123!"
    hashed = get_password_hash(password)
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("wrong_password", hashed) is False

def test_jwt_generation():
    data = {"user_id": 123}
    token = create_access_token(data)
    assert isinstance(token, str)
    assert len(token) > 20
