import pytest
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture(scope="module")
def client():
    return TestClient(app)

@pytest.fixture(scope="module")
def auth_headers(client):
    # register & login one user
    email = "forum_user@test.io"
    pw = "Forum123!"
    client.post("/auth/register", json={"email": email, "password": pw})
    login = client.post("/auth/login", json={"email": email, "password": pw})
    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_get_topics_pagination(client, auth_headers):
    for i in range(25):
        client.post(
            "/forum/topics",
            json={"title": f"Topic number {i:02d}", "content": "x" * 20},
            headers=auth_headers
        )

    # page=1 → 20 items
    r1 = client.get("/forum/topics?page=1")
    assert r1.status_code == 200
    data1 = r1.json()
    assert isinstance(data1, list) and len(data1) == 20

    # page=2 → 5 items
    r2 = client.get("/forum/topics?page=2")
    assert r2.status_code == 200
    data2 = r2.json()
    assert isinstance(data2, list) and len(data2) == 5

def test_post_endpoints_require_auth(client):
    # create-topic without JWT → 401
    r1 = client.post("/forum/topics", json={"title": "Valid Title Here", "content": "x" * 20})
    assert r1.status_code == 401

    # create-post without JWT → 401
    r2 = client.post("/forum/topics/1/posts", json={"content": "Hello"})
    assert r2.status_code == 401

def test_create_topic_validation_errors(client, auth_headers):
    # title too short & content too short → 422
    r = client.post(
        "/forum/topics",
        json={"title": "short", "content": "too small"},
        headers=auth_headers
    )
    assert r.status_code == 422
    errs = r.json()["detail"]
    assert any(e["loc"][-1] == "title" for e in errs)
    assert any(e["loc"][-1] == "content" for e in errs)

def test_create_post_validation_error(client, auth_headers):
    # first create a valid topic
    topic = client.post(
        "/forum/topics",
        json={"title": "A Valid Title Here", "content": "y" * 20},
        headers=auth_headers
    ).json()

    # now try to post invalid content
    r = client.post(
        f"/forum/topics/{topic['id']}/posts",
        json={"content": ""},
        headers=auth_headers
    )
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert any(e["loc"][-1] == "content" for e in detail)

def test_happy_path_create_topic_and_post(client, auth_headers):
    # create-topic happy path
    ct = client.post(
        "/forum/topics",
        json={"title": "Test Topic Title", "content": "This is valid content of at least 20 chars."},
        headers=auth_headers
    )
    assert ct.status_code == 201
    topic = ct.json()
    assert "id" in topic and topic["title"] == "Test Topic Title"

    # create-post happy path
    cp = client.post(
        f"/forum/topics/{topic['id']}/posts",
        json={"content": "This is my reply."},
        headers=auth_headers
    )
    assert cp.status_code == 201
    post_body = cp.json()
    assert "id" in post_body