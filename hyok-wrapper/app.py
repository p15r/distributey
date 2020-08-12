import jwe
from markupsafe import escape
from flask import request
from flask import Flask


app = Flask(__name__)


@app.route('/<string:kid>', methods=['GET'])
def get_jwe_token(kid: str = ''):
    """
    kid: kid provided by Salesforce. Mandatory.
    nonce: Nonce (?requestId=xxx) provided by Salesforce to prevent replay attacks. Optional.
    """

    json_jwe_token = jwe.generate_jwe(
        kid=str(escape(kid)),
        nonce=str(escape(request.args.get('requestId', ''))))

    if not json_jwe_token:
        return 'Oops, internal error.', 500

    return json_jwe_token
