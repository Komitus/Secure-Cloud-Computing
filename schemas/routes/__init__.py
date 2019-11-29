from flask import Blueprint, jsonify
from flask import current_app
implemented_protocols = ["sis", "ois", "sss", "msis", "blsss", "gjss", "naxos", "sigma"]

bp = Blueprint("protocols", __name__)

@bp.route("/")
def index():
    current_app.logger.info(f'Implemented protocols: {str(implemented_protocols)}')
    return jsonify({
        "schemas" : implemented_protocols
        })


from .sis import routes as sis_routes
from .ois import routes as ois_routes
from .sss import routes as sss_routes
from .msis import routes as msis_routes
from .blsss import routes as blsss_routes
from .gjss import routes as gjss_routes
from .naxos import routes as naxos_routes
from .sigma import routes as sigma_routes

routes = (
    sis_routes + 
    ois_routes +
    sss_routes +
    msis_routes +
    blsss_routes +
    gjss_routes +
    naxos_routes +
    sigma_routes
)

for r in routes:
    bp.add_url_rule(
        r['rule'],
        endpoint= r.get('endpoint', None),
        view_func= r['view_func'],
        **r.get('options', {})
    )