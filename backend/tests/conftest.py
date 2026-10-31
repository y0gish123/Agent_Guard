"""Pytest fixtures for AgentGuard AI SOC tests."""

import os
import tempfile
import threading
import time
import pytest
from fastapi.testclient import TestClient
import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import uvicorn

# Environment variables for tests
os.environ["HMAC_SECRET"] = "test-hmac-secret-key-32charslong!!"
os.environ["SIMULATION"] = "true"
os.environ["DEMO_MODE"] = "guarded"
os.environ["TOOL_URL"] = "http://127.0.0.1:8001"

from backend.config import get_settings
from backend.db.models import Base
from backend.db.session import get_db
from backend.main import create_app
from mock_tool.app import app as mock_app, state_manager, get_verifier


@pytest.fixture(scope="session", autouse=True)
def mock_tool_server():
    """Start mock tool server on 127.0.0.1:8001 for integration testing."""
    config = uvicorn.Config(
        mock_app,
        host="127.0.0.1",
        port=8001,
        log_level="error",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait until server is accepting connections
    deadline = time.time() + 5.0
    ready = False
    while time.time() < deadline:
        try:
            with httpx.Client(timeout=0.5) as client:
                r = client.get("http://127.0.0.1:8001/tool/state")
                if r.status_code == 200:
                    ready = True
                    break
        except Exception:
            time.sleep(0.1)

    assert ready, "Mock tool server failed to start within timeout"
    yield server
    server.should_exit = True


@pytest.fixture
def test_db():
    """Create a temporary SQLite database per test."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    test_db_url = f"sqlite:///{db_path}"
    engine = create_engine(test_db_url, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    yield override_get_db, test_db_url

    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    try:
        os.remove(db_path)
    except Exception:
        pass


@pytest.fixture
def client(test_db):
    override_get_db, _ = test_db
    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def mock_client():
    with TestClient(mock_app) as client:
        yield client
