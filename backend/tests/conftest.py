import pytest
from datetime import timedelta
from core.security import create_access_token

@pytest.fixture
def test_content():
    return "import socket; s=socket.socket(); s.connect(('127.0.0.1', 4444))"

@pytest.fixture
def valid_token():
    return create_access_token(data={"sub": "testuser"}, expires_delta=timedelta(minutes=15))
