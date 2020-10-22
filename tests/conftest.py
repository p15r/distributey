import pytest
from app import app
from werkzeug.datastructures import Headers
import dev.create_jwt


# TODO: return vs yield

def get_jwt():
    return dev.create_jwt.token


@pytest.fixture(name='get_jwt')
def get_jwt_fixture():
    return get_jwt()


@pytest.fixture()
def get_protected_headers():
    # ascii_b64_protected_header
    return (
            b'eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5'
            b'jIjogIkEyNTZHQ00iLCAia2lkIjogIm'
            b'p3ZS1raWQtc2FsZXNmb3JjZS1zZXJ2a'
            b'WNlWCIsICJqdGkiOiAibm9uY2UifQ==')


@pytest.fixture
def get_headers():
    return Headers([
        ('X-Real-Ip', '172.20.0.1'),
        ('Host', 'up-hyok-wrapper'),
        ('Connection', 'close'),
        ('User-Agent', 'curl/7.68.0'),
        ('Accept', '*/*'),
        ('Authorization', f'Bearer {get_jwt()}')])


@pytest.fixture
def get_jwt_signing_pubkey():
    return open('dev/tmp/jwt.pub').read()


@pytest.fixture
def http_client():
    app.config['TESTING'] = True

    with app.test_client() as client:
        yield client
