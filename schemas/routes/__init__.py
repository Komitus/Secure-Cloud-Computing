from .one_of_two import routes as one_of_two_routes
from .one_of_n import routes as one_of_n_routes
from flask import Blueprint, jsonify
from flask import current_app
implemented_protocols = ["one_of_two", "one_of_n"]

bp = Blueprint("protocols", __name__)


@bp.route("/")
def index():
    current_app.logger.info(
        f'Implemented protocols: {str(implemented_protocols)}')
    return jsonify({
        "schemas": implemented_protocols
    })


routes = (
    one_of_two_routes +
    one_of_n_routes
)

for r in routes:
    bp.add_url_rule(
        r['rule'],
        endpoint=r.get('endpoint', None),
        view_func=r['view_func'],
        **r.get('options', {})
    )
