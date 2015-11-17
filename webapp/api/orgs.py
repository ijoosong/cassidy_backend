from flask import request, jsonify
from flask.views import MethodView
from webapp.model import Org
from webapp import rbac
from webapp.model import db
from sqlalchemy.exc import IntegrityError


class Orgs(MethodView):
    """
    Endpoint for Orgs:
    Get orgs and shows organizations.
    Post creates orgs.
    """
    decorators = [rbac.allow(['api'], ['GET', 'POST', 'PUT'])]

    def get(self, org_id=None):
        """
        get orgs
        ---
        tags:
          - orgs
        responses:
          200:
            schema:
              id: basic_out
        """
        if org_id is None:
            orgs = Org.query.all()
            org_list = [o.as_json() for o in orgs]
            return jsonify(orgs=org_list), 200
        org = Org.query.filter_by(id=org_id).first()
        if not org:
            return jsonify(error="no orgs found under that org id"), 400
        return jsonify(org.as_json()), 200

    def post(self):
        """
        creates a org given a name for the organization. bic_id optional
        ---
        tags:
          - orgs
        parameters:
          - in: body
            name: body
            schema:
              id: org_in
              properties:
                name:
                  type: string
                bic_id:
                  type: integer
        responses:
          201:
            schema:
              id: basic_out
        """
        print "\n\n\n\n\n\n\n"
        name = request.json.get("name", None)
        if name is None:
            return jsonify(error="name parameter required"), 400
        org = Org.query.filter_by(name=name).first()
        if org is not None:
            return jsonify(error="Org name already exists"), 400
        o = Org(name=name)
        db.session.add(o)
        db.session.commit()
        return jsonify(o.as_json()), 201

    def put(self, org_id=None):
        """
        change org name
        ---
        tags:
          - orgs
        parameters:
          - in: body
            name: body
            schema:
              id: change_org
              properties:
                name:
                  type: string
        responses:
          201:
            schema:
              id: basic_out
        """
        org = Org.query.filter_by(id=org_id).first()
        if org is None:
            return jsonify(error="organization does not exist"), 404
        new_name = request.json.get('name')
        try:
            org.name = new_name
            db.session.add(org)
            db.session.commit()
        except IntegrityError as e:
            if e.orig.pgcode == "23505":
                return jsonify(error='name is already in use by another org'), 400
        return jsonify(org.as_json()), 201
