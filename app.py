from flask import Flask
from flask_rbac import RBAC

rbac = RBAC()


def create_app():
    app = Flask(__name__)

    rbac.init_app(app)

    return app
