import wsgi     # noqa: F401


def test_connect_to_app(http_client):
    response = http_client.get('/')
    assert response.status_code == 404
