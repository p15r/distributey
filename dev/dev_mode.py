"""Runs flask development server."""
import os
import sys

dy_path = os.path.abspath(os.getcwd())
sys.path.append(os.path.join(dy_path, 'distributey'))

os.environ['DY_CFG_PATH'] = 'config/config.json'

from app import app # noqa

if __name__ == '__main__':
    app.run(debug=True)

    # TODO:
    # set app.config['TESTING'] = True
    # (or only required for running unittests?)
