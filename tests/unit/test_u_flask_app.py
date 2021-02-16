"""Test module for Flask app."""

import os
from stat import S_IREAD, S_IRGRP, S_IROTH, S_IWUSR
import pytest
import jwt
import app
import werkzeug
import config


class TestUnitFlaskApp():
    """Test class for Flask app."""
    def test__get_kid_from_jwt(self, get_jwt):
        assert app._get_kid_from_jwt(get_jwt) == 'jwt_kid_salesforce_serviceX'

        # test w/ invalid jwt protected header
        split_protected_header = get_jwt.split('.')
        split_protected_header[0] = split_protected_header[0] + 'badstring'
        bad_jwt = '.'.join(split_protected_header)

        kid = app._get_kid_from_jwt(bad_jwt)

        if kid:
            assert False, ('Should fail if protected header is malformed.'
                           f'Got kid "{kid}".')
        else:
            assert True, 'Failed as expected on malformed protected header.'

    def test__get_jwt_from_header(self, get_headers, get_jwt):
        # test w/ valid token
        assert app._get_jwt_from_header('Bearer ' + get_jwt) == get_jwt

        # test w/ invalid header format
        assert app._get_jwt_from_header('Bearer Bearer' + get_jwt) == ''
        assert app._get_jwt_from_header('Bearer ') == ''

        # test w/ headers w/o bearer token
        assert app._get_jwt_from_header(get_jwt) == ''

    def test__decode_jwt(self, monkeypatch, get_jwt, get_jwt_signing_pubkey):
        assert app._decode_jwt(
            'salesforce', get_jwt, get_jwt_signing_pubkey) == \
            ('cacheonlyservice', 'salesforce')

        # test w/ non existing tenant
        try:
            app._decode_jwt(
                'nonexistingtenant', get_jwt, get_jwt_signing_pubkey)
            assert False, 'Should fail if non existing tenant is given.'
        except werkzeug.exceptions.HTTPException:
            assert True, 'Failed as expected on non existing tenant.'

        # test w/ invalid signature
        invalid_s = ('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZC'
                     'I6Imp3dF9raWRfc2FsZXNmb3JjZV9zZXJ2aWNlWCJ9.eyJzdW'
                     'IiOiJjYWNoZW9ubHlzZXJ2aWNlIiwiaXNzIjoic2FsZXNmb3J'
                     'jZSIsImF1ZCI6InVybjpoeW9rLXdyYXBwZXIiLCJpYXQiOjE2'
                     'MDM2NTE2MTMsImV4cCI6MTYwMzY1MTkxM30.NBhBFYLm4ySZq'
                     'Dk5sYJtv0NY56Ti3SgB6BrO1iE7tdOBMmjM6BSNQDaRBscURw'
                     'ZuQWNM2f2Leab4Kgf1wax5O9KrRJpD6Ym4jBH2xTHtgzxLfUF'
                     'kEihyVEpLes0Nf2e-w0efOq5Ayqmo_KfmlTqP1PK37U9CaIub'
                     'yqKYOSFAbclQ4rEkiZOM38--iJbd6syJ6W0nnEUvgRaQichZK'
                     '3mN3Gdo46C-WUY21MPOy_6qz4WGu6qCAEjBePmt_-3dOpPKQR'
                     '0CGCKTtCP8psga3M6W9WUgaCpgYnDS-YQdEnD3VG575J-1Cmd'
                     'cShKc-Fo2F-FWpybcP98hMaFg2sQfgjgFNg')

        assert app._decode_jwt(
            'salesforce', invalid_s, get_jwt_signing_pubkey) == ('', '')

        # test w/ expired token
        expired_sig_token = ('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZ'
                             'CI6Imp3dF9raWRfc2FsZXNmb3JjZV9zZXJ2aWNlWC'
                             'J9.eyJzdWIiOiJjYWNoZW9ubHlzZXJ2aWNlIiwiaX'
                             'NzIjoic2FsZXNmb3JjZSIsImF1ZCI6InVybjpkaXN'
                             '0cmlidXRleVhYWFhYWCIsImlhdCI6MTYxMzQ1Nzg0'
                             'NiwiZXhwIjoxNjEzNDU4MTQ2fQ.kZ-1h7KaP75CXJ'
                             'ZIslyg2sPmRge2eH0U2xtgHbkpm7SijYnpA7Y2DLq'
                             '5K2wupXj-E9nSXddixJu3KCiGeGw7P_CdESrjSalH'
                             'LLnAdqJ9v_swEydEu00cxTyV063bh008zegzm06Ub'
                             'eSk8Dwc7n8De8bgFev97L2B16JG89UrSR7tUJMgfc'
                             '5DAYjjw6W_GW_8YevzmkrjhAFYOpXsK5VESBZ9E77'
                             'iGS2HzKJ0jw6m0bw3QGvwH9RKYSARVqm-gXt8trvW'
                             'ZVnlVcZXuRu2tqQIKWpP2vxvn_wnMoG-FUw0PBCdC'
                             '5GBaz1laNMNLEB2_piP-uxO69lhXWoQnoFR-NhhSi'
                             'Gv8FG_ozt7ddAWREM_dMbpTe-zBohosYd3r3c_Sna'
                             'KXO61zOdXTBDm3l0Ie86JRX9_xM1vVnvrsckpA5ly'
                             'kzMHHOK-gKBX7jDwVRdnGCUXkJZc5KbaYIoXoQIen'
                             'ObS65eSCV4Nq698fbx7Bz3BWVK4fSRw0zO0HMYTNx'
                             'kdretWtUU84AHzMIODRkLX608XgiFiAxLvqNOcOTF'
                             'vWomnlgqQQgge5qF1JhrQYjGZ4HU_8O8rLxeRyOpa'
                             '2zCIGbGakZ7iHWavTFARmWyTnoImrxN2INSdiGGqj'
                             'AupunU64ZOdmkgQZL8eSlY4RHBsS9jf07R1Li2BFb'
                             'u3dF0Bv6FiPF4')

        assert app._decode_jwt('salesforce', expired_sig_token,
                               get_jwt_signing_pubkey) == ('', '')

        # test w/ missing exp claim
        invalid_aud_token = ('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZ'
                             'CI6Imp3dF9raWRfc2FsZXNmb3JjZV9zZXJ2aWNlWC'
                             'J9.eyJzdWIiOiJjYWNoZW9ubHlzZXJ2aWNlIiwiaX'
                             'NzIjoic2FsZXNmb3JjZSIsImF1ZCI6InVybjpkaXN'
                             '0cmlidXRleVhYWFhYWCIsImlhdCI6MTYxMzQ1ODcw'
                             'Mn0.UpXtLj214gEnipiNBMF-X0M5vPCPSzxIO8HmM'
                             '3UkRGICPNkMKO5W0CstowrgalzjEoj-tX_s3YiFCo'
                             'mJpH4-NBw2WcpcCBmSoSCyURWlfW8Rn0VrYZyMDk5'
                             'AVx_v6hbRHB2hsxeGoj51DxOGAdyt6V-0HnsJq5q8'
                             'yx_AP2Ppd8apr5oWIpNTP1VP8TraJrBF-octZBjnE'
                             'FSeS2b2zJgYxczc4rstfaPsBSXHOpf12SqGUBoXFM'
                             'nhopVbuW0xd_7N2twPm5uNhyy1I5ftniv95zEckKy'
                             '0mU3k7UM2V2cO4pIEFEMSzwpPJPhHQhBgcisrbjia'
                             'VAci4aqJQB5TjojeaawVBScH0Pao2ifAX8BO-SeYW'
                             'Sc9RuyyDRSwped2ERQOSWv8BuKOuoV5p3aKWi1Ect'
                             'MVoJyTiavIQcKBpP4cxvoYJZSzTLvZCDqn0btjX2p'
                             'AnkHKhAvS5iqy9NmjXk935ZlyuENLYEyihXh8qLJ8'
                             'QokgTXQH62JWyWshuY1DhkH7EWE_0wIlq923L_MFG'
                             'axWaL5zG-qCpo3yhEPuMD_VE_zqATV0mK-6suBeez'
                             'CBMQx5m0CCV4AW9vX8P31jy240GhsJ3YSLElbGD6d'
                             '8OA4KqIyBTsd6u3EaDpld8lygFBDJN-bCEw8p0Rp9'
                             'YChTjntesdf88mAjGZDGIrHD9uIFNQY===')

        with pytest.raises(jwt.exceptions.MissingRequiredClaimError):
            app._decode_jwt('salesforce', invalid_aud_token,
                            get_jwt_signing_pubkey)

        # test w/ invalid audience claim
        invalid_aud_claim = ('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZ'
                             'CI6Imp3dF9raWRfc2FsZXNmb3JjZV9zZXJ2aWNlWC'
                             'J9.eyJzdWIiOiJjYWNoZW9ubHlzZXJ2aWNlIiwiaX'
                             'NzIjoic2FsZXNmb3JjZSIsImF1ZCI6InVybjpkaXN'
                             '0cmlidXRleVhYWFhYWCIsImlhdCI6MTYxMzQ1OTEx'
                             'MywiZXhwIjozMzExNzkyMzExM30.rSuK2OjZWeyqy'
                             'RXmp3-8qxSqZkPa2Ebwe67Dye1EWvIxi6Tsdfbd8x'
                             'INKZSrwCteSYFbJTtMrtVZl7vkG-wdvkXJ-iQBffk'
                             'btWwWsYcJHbZwb-YioBIlsrNjAv-TAFqhd6Vrom__'
                             'jCmWX6M5vSkS97sDZQgtpnti0ZVQpzTwMZHz27L9P'
                             'euMJvjHP5V0Oau_CJrXymhO17g34Bhs_IWDglW8nP'
                             '0xpV_myz_gywiQZoT4zzSvFcn4o2iozm7xRZynkrZ'
                             'V0CgD_guUcdMcfhNI1wuRxS-u2YODY5hYxefTYfHj'
                             'pxZ7zqXL_1D_8SbnlCY0j7mdag6mH_KeVmmZGhzXo'
                             'Q0LzXDnEdC2sisCDN18oSzgEnXwHWV7WKp4RIjQEZ'
                             'CLwfhQS8I0308HnKmBwy22ghHrQMS4E3wD0NXaZDD'
                             'ZxYukAJecK4ScEsrHBq-XLPWw5WFOIUn6uhhEWM0n'
                             'ud5SHnun-zrVFainAqqL6pNFbGzWrbpOoQWGZz-2x'
                             'vB9V-zawYlgJunNQLM-Onr6ZwSYhbOwPwZMrpTojr'
                             'ldjR3vPX0zlIvdD3OtFn-CjkFq9servXcciYuCN8e'
                             'uIrROnkw-3LO5pCzLF0TowRgRXF7sn3p4UAHknezh'
                             'wTSjj7Rt6Upg-uF-VwQ88ByM2L2GC112DNvzi2MEX'
                             'WlF4seaHjHDFM4')

        assert app._decode_jwt('salesforce', invalid_aud_claim,
                               get_jwt_signing_pubkey) == ('', '')

        # test invalid jwt algo cfg
        def mock_config_get_jwt_algorithm_by_tenant(*args):
            return ''

        monkeypatch.setattr(config, 'get_jwt_algorithm_by_tenant',
                            mock_config_get_jwt_algorithm_by_tenant)

        # should return http 500
        with pytest.raises(werkzeug.exceptions.HTTPException):
            app._decode_jwt(
                'salesforce', get_jwt, get_jwt_signing_pubkey)

    def test___authenticate(self, get_headers, get_jwt):
        assert app._authenticate('salesforce', 'Bearer ' + get_jwt) == get_jwt

    def test_get_wrapped_key_no_auth(
            self, http_client, get_jwt, get_endpoint_url,
            get_endpoint_url_nonexistingtenant):
        # this integration test runs here, because it has no runtime deps
        headers = {'X_REAL_IP': '127.0.0.1'}

        # access API w/o Authorization header
        response = http_client.get(get_endpoint_url, headers=headers)
        assert response.status_code == 422

        # access API w/ wrong tenant
        response = http_client.get(
            get_endpoint_url_nonexistingtenant, headers=headers)
        assert response.status_code == 422

        # further coverage requires Vault, thus covered w/ integration tests

    def test_get_healthz(self, monkeypatch, http_client):
        endpoint = '/v1/healthz'
        headers = {'X_REAL_IP': '127.0.0.1'}

        response = http_client.get(endpoint, headers=headers)
        assert response.status_code == 200

        # test w/o available config file
        monkeypatch.setattr(
            config, '__CFG_PATH', 'config/NONEXISTINGCONFIG.json')

        response = http_client.get(endpoint, headers=headers)
        assert response.status_code == 500

    def test___user_agent_validator(
            self, http_client, get_endpoint_url, get_headers):
        """
        Issues invalid HTTP request and validates response.
        This test also covers "__handle_request_parsing_error()".
        """

        # set invalid UA to trigger error
        headers = get_headers
        headers['User-Agent'] = 'NoValueAfterSlash/'

        response = http_client.get(get_endpoint_url, headers=headers)

        assert response.status_code == 422
        assert response.json == \
            {'headers':
             {'user-agent':
              ['User agent pattern does not match "name/version"']}}
        assert response.mimetype == 'application/json'
        assert response.charset == 'utf-8'

    def test___x_real_ip_validator(
            self, http_client, get_endpoint_url, get_headers):
        headers = get_headers
        headers['X-Real-Ip'] = '1'

        response = http_client.get(get_endpoint_url, headers=headers)

        assert response.status_code == 422
        assert response.json == \
            {'headers':
             {'X-Real-Ip':
              ['X-Real-Ip must be between 7 and 15 characters long.']}}

        headers['X-Real-Ip'] = '012345678'

        response = http_client.get(get_endpoint_url, headers=headers)

        assert response.status_code == 422
        assert response.json == \
            {'headers':
             {'X-Real-Ip':
              ['X-Real-Ip format does not match: '
               'digits.digits.digits.digits.']}}

        headers['X-Real-Ip'] = '127.0.0.1111'
        response = http_client.get(get_endpoint_url, headers=headers)

        assert response.status_code == 422
        assert response.json == \
            {'headers':
             {'X-Real-Ip':
              ['X-Real-Ip format does not match: x.x.x.x-xxx.xxx.xxx.xxx']}}

    def test__initialize_cache_db(self, monkeypatch):
        monkeypatch.setattr(app, '__CACHE_DB', '/nontexistingpath/')

        ret = app._initialize_cache_db()

        assert ret is False

    def test__is_replay_attack(self, monkeypatch, capfd):
        nonce = '12345678901234567890123456789012'

        # valid test
        assert app._is_replay_attack(nonce) is False

        # test replay attack
        assert app._is_replay_attack(nonce) is True

        # test w/ small cache
        monkeypatch.setattr(app, '__CACHE_DB_NR_ENTRIES', 0)
        assert app._is_replay_attack('12345678901234567890123456789011') is \
            False

        # test w/ read-only file
        tmp_cache_db = getattr(app, '__CACHE_DB')
        os.chmod(tmp_cache_db, S_IREAD | S_IRGRP | S_IROTH)

        app._is_replay_attack('12345678901234567890123456789013')
        out, err = capfd.readouterr()

        pos = err.find('Failed to write replay attack cache db: '
                       '[Errno 13] Permission denied:')
        assert pos > -1     # if pos > -1, the string has been found

        # make file writable again
        os.chmod(tmp_cache_db, S_IWUSR | S_IREAD)

        # test w/ invalid path for cache db
        monkeypatch.setattr(app, '__CACHE_DB', '/nonexistingpath/')
        assert app._is_replay_attack(nonce) is True
