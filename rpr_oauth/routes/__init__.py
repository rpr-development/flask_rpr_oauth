from flask import Blueprint

oauth = Blueprint('oauth', __name__, url_prefix='/oauth')

from . import routes