import os

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'PasswordManager.sqlite'),
    )

    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    from . import db
    db.init_app(app)

    from . import auth
    limiter = Limiter(app, default_limits = ["1/second"], key_func=get_remote_address)
    limiter.limit("60/hour")(auth.bp)
    app.register_blueprint(auth.bp)

    from . import manager
    app.register_blueprint(manager.bp)
    app.add_url_rule('/', endpoint='index')

    return app