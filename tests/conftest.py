import os
import pytest
import app
from werkzeug.datastructures import Headers
import dev.create_jwt
import config


# Note about yield vs return:
# By using a yield statement instead of return,
# all the code after the yield statement serves as the teardown code.

def get_jwt():
    return dev.create_jwt.token


@pytest.fixture(name='get_endpoint_url')
def get_endpoint_url():
    return ('/v1/salesforce/jwe-kid-salesforce-serviceX'
            f'?requestId={os.urandom(16).hex()}')


@pytest.fixture(name='get_endpoint_url_nonexistingtenant')
def get_endpoint_url_nonexistingtenant():
    return ('/v1/nontexistingtenant/jwe-kid-salesforce-serviceX'
            f'?requestId={os.urandom(16).hex()}')


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
        ('Host', 'up-distributey'),
        ('Connection', 'close'),
        ('User-Agent', 'curl/7.68.0'),
        ('Accept', '*/*'),
        ('Authorization', f'Bearer {get_jwt()}')])


@pytest.fixture
def get_jwt_signing_pubkey():
    with open('dev/tmp/jwt.pub') as f:
        cnt = f.read()

    return cnt


@pytest.fixture
def http_client():
    app.app.config['TESTING'] = True

    with app.app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def setup_module(monkeypatch, tmpdir):
    monkeypatch.setattr(config, '__CFG_PATH', 'config/config.json')

    # TODO: distributey keeps track of nonces in a db located in /tmp.
    # For testing, a dedicated location for temporary files is provided
    # by pytest.
    # However, importing the "app" module leads to the creation of
    # /tmp/cache.db, which is ugly. It would be better to initialize the
    # cache db outside the app module in a place that is executed before flask
    # starts. E.g. in "entrypoint.sh".

    # create tmp dir for cache db
    test_cache_db = tmpdir.mkdir('cachedb').join('test_cache.db')
    monkeypatch.setattr(app, '__CACHE_DB', test_cache_db)

    # initialize cache db in mocked dir
    app._initialize_cache_db()
