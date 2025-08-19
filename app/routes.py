from flask import Blueprint

bp = Blueprint("routes", __name__)

@bp.route("/")
def hello():
    return "Hello, Family Password Manager!"
