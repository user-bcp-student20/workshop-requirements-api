import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.main import create_app


JWT_ISSUER = "workshop-auth"
JWT_AUDIENCE = "workshop-requirements-api"


@pytest.fixture
def jwt_private_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> bytes:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key_path = tmp_path / "auth-public.pem"
    public_key_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setenv("AUTH_JWT_PUBLIC_KEY_PATH", str(public_key_path))
    return private_key_bytes


def token(private_key: bytes, username: str = "student", role: str = "STUDENT", **overrides: object) -> str:
    now = int(time.time())
    claims: dict[str, object] = {
        "sub": username,
        "groups": [role],
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + 3600,
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="RS256")


def headers(private_key: bytes, username: str = "student", role: str = "STUDENT") -> dict[str, str]:
    return {"Authorization": f"Bearer {token(private_key, username, role)}"}


def test_lists_seeded_tasks(tmp_path: Path, jwt_private_key: bytes) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        response = client.get("/api/tasks", headers=headers(jwt_private_key))
    assert response.status_code == 200
    assert len(response.json()) == 2


def test_creates_task_and_summary(tmp_path: Path, jwt_private_key: bytes) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        created = client.post(
            "/api/tasks",
            headers=headers(jwt_private_key),
            json={"title": "Add tests", "description": "Improve coverage", "status": "TODO", "priority": "HIGH"},
        )
        summary = client.get("/api/summary", headers=headers(jwt_private_key))
    assert created.status_code == 201
    assert created.json()["owner"] == "student"
    assert summary.json()["total"] == 3


def test_uploads_requirement(tmp_path: Path, jwt_private_key: bytes) -> None:
    upload_dir = tmp_path / "uploads"
    app = create_app(str(tmp_path / "workshop.db"), str(upload_dir))
    with TestClient(app) as client:
        response = client.post(
            "/api/requirements",
            headers=headers(jwt_private_key),
            files={"file": ("requirements.txt", b"Login must be accessible", "text/plain")},
        )
    assert response.status_code == 201
    assert (upload_dir / "requirements.txt").exists()


def test_rejects_invalid_token(tmp_path: Path, jwt_private_key: bytes) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        response = client.get("/api/tasks", headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 401


def test_rejects_token_signed_by_another_key(tmp_path: Path, jwt_private_key: bytes) -> None:
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_private_key = other_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    invalid_token = token(other_private_key)
    with TestClient(app) as client:
        response = client.get("/api/tasks", headers={"Authorization": f"Bearer {invalid_token}"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid token"}


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "untrusted-issuer"},
        {"aud": "other-service"},
        {"exp": 1},
    ],
    ids=["wrong-issuer", "wrong-audience", "expired"],
)
def test_rejects_invalid_claims(tmp_path: Path, jwt_private_key: bytes, claims: dict[str, object]) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    invalid_token = token(jwt_private_key, **claims)
    with TestClient(app) as client:
        response = client.get("/api/tasks", headers={"Authorization": f"Bearer {invalid_token}"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid token"}


def test_rejects_legacy_format(tmp_path: Path, jwt_private_key: bytes) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        response = client.get("/api/tasks", headers={"Authorization": "Bearer student|STUDENT|legacy"})
    assert response.status_code == 401


def test_authentication_requires_public_key_configuration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUTH_JWT_PUBLIC_KEY_PATH", raising=False)
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        response = client.get("/api/tasks", headers={"Authorization": "Bearer token"})
    assert response.status_code == 503
