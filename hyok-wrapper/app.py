import jwe
from flask import Flask
app = Flask(__name__)


@app.route('/')
def get_jwe_token():
    json_jwe_token = jwe.generate_jwe()
    return json_jwe_token


if __name__ == '__main__':
    app.run(host='0.0.0.0')
