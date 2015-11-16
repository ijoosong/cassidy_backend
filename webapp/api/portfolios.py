from flask import request, jsonify
from flask.views import MethodView
from webapp.model import Org, Portfolio
from webapp import rbac
from webapp.model import db


class OrgPortfolios(MethodView):
    """
    Endpoint for Portfolios:
    Get user portfolios given user.
    Post creates portfolios under given user.
    """
    #decorators = [rbac.allow(['api'], ['GET', 'POST'])]

    def get(self, org_id=None):
        """
        This is the endpoint that returns all org portfolios given an org id
        """
        if org_id is None:
            return jsonify(error="Need to put in org_id"), 404
        portfolios = Portfolio.query.filter_by(org_id=org_id).all()
        if len(portfolios) == 0:
            return jsonify(error="no portfolios found under org"), 400
        portfolio_list = [p.as_json() for p in portfolios]
        return jsonify(portfolios=portfolio_list)

    def post(self, org_id=None):
        """
        This function creates a portfolio for a user given org id and portfolio name
        """
        if org_id is None:
            return jsonify(error="Need to put in org_id"), 404
        name = request.json.get("name", None)
        if name is None:
            return jsonify(error="name parameter required"), 400
        portfolios = Portfolio.query.filter_by(org_id=org_id)
        for p in portfolios:
            if name == p.name:
                return jsonify(error="Portfolio name already exists for this org"), 400

        o = Org.query.filter_by(id=org_id).first()
        p = Portfolio(name=name, org=o)
        db.session.add(p)
        db.session.commit()

        return jsonify(portfolio=p.as_json()), 201


class Portfolios(MethodView):
    decorators = [rbac.allow(['api'], ['GET',])]

    def get(self):
        """
        This is the endpoint that returns all portfolios
        """

        portfolios = Portfolio.query.all()
        if len(portfolios) == 0:
            return jsonify(error="no portfolios found"), 400
        portfolio_list = [p.as_json() for p in portfolios]
        return jsonify(portfolios=portfolio_list)
