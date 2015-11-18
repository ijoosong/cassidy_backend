from flask import Blueprint, jsonify
from portfolios import OrgPortfolios, Portfolios
from userAdmin import UserAdmin, UserNew2FA
from roles import Roles, UserRoles
from apikeys import Api_Keys
from orgs import Orgs
from teams import Teams
from flask_swagger import swagger


api = Blueprint('api', __name__)


def register_api(view, endpoint, url, pk='user_id', pk_type='int'):
    view_func = view.as_view(endpoint)
    if pk:
        api.add_url_rule(url, defaults={pk: None}, view_func=view_func, methods=['GET', 'PUT'])
        api.add_url_rule(url, view_func=view_func, methods=['POST', ])
        api.add_url_rule('%s<%s:%s>' % (url, pk_type, pk), view_func=view_func,
                         methods=['GET', 'PUT', 'POST'])
    else:
        api.add_url_rule(url, view_func=view_func, methods=['GET', ])
        api.add_url_rule(url, view_func=view_func, methods=['POST', ])


def register_sub_api(view, endpoint, url, pk, pk_type='int'):
    view_func = view.as_view(endpoint)
    api.add_url_rule(url % (pk_type, pk), view_func=view_func, methods=['GET', ])
    api.add_url_rule(url % (pk_type, pk), view_func=view_func, methods=['POST', ])


def register_api_get(view, endpoint, url, pk='user_id', pk_type='int'):
    view_func = view.as_view(endpoint)
    if pk:
        api.add_url_rule(url, defaults={pk: None}, view_func=view_func, methods=['GET', ])
        api.add_url_rule('%s<%s:%s>' % (url, pk_type, pk), view_func=view_func,
                         methods=['GET', ])
    else:
        api.add_url_rule(url, view_func=view_func, methods=['GET', ])


def register_sub_api_get(view, endpoint, url_rules, pk_type='int'):
    view_func = view.as_view(endpoint)
    for url_rule, pk, verb in url_rules:
        api.add_url_rule(url_rule % (pk_type, pk), view_func=view_func, methods=[verb, ])


register_api(UserAdmin, 'userAdmin', '/users/')
register_api(UserNew2FA, 'userNew2FA', '/users/2fa/')
register_api(Api_Keys, 'apikeys', '/apikeys/')
register_api(Orgs, 'orgs', '/orgs/', pk='org_id')
register_api(Teams, 'teams', '/teams/', pk='team_id')

register_sub_api(UserRoles, 'userRoles', '/users/<%s:%s>/roles/', pk="user_id")
register_sub_api(OrgPortfolios, 'orgPortfolios', '/orgs/<%s:%s>/portfolios/', pk="org_id")

register_api_get(Roles, 'roles', '/roles/', pk='role_id')
register_api_get(Portfolios, 'portfolios', '/portfolios/', pk=None)


@api.route('/docs')
def documentation():
    return jsonify(swagger(api))
