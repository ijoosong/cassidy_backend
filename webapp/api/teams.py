from flask import request, jsonify
from flask.views import MethodView
from webapp.model import Team
from webapp import rbac
from webapp.model import db
from sqlalchemy.exc import IntegrityError


class Teams(MethodView):
    """
    Endpoint for Teams:
    Get teams.
    Post creates teams.
    """
    decorators = [rbac.allow(['api'], ['GET', 'POST', 'PUT'])]

    def get(self, team_id=None):
        """
        get teams
        ---
        tags:
          - teams
        responses:
          200:
            schema:
              id: basic_out
        """
        if team_id is None:
            teams = Team.query.all()
            team_list = [t.as_json() for t in teams]
            return jsonify(orgs=team_list), 200
        team = Team.query.filter_by(id=team_id).first()
        if not team:
            return jsonify(error="no teams found under that team id"), 400
        return jsonify(team.as_json()), 200

    def post(self):
        """
        creates a org given a name for the organization. bic_id optional
        ---
        tags:
          - teams
        parameters:
          - in: body
            name: body
            schema:
              id: teams_in
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
        name = request.json.get("name", None)
        if name is None:
            return jsonify(error="name parameter required"), 400
        team = Team.query.filter_by(name=name).first()
        if team is not None:
            return jsonify(error="Team name already exists"), 400
        t = Team(name=name)
        db.session.add(t)
        db.session.commit()
        return jsonify(t.as_json()), 201

    def put(self, team_id=None):
        """
        change org name
        ---
        tags:
          - teams
        parameters:
          - in: body
            name: body
            schema:
              id: change_teams
              properties:
                name:
                  type: string
        responses:
          201:
            schema:
              id: basic_out
        """
        team = Team.query.filter_by(id=team_id).first()
        if team is None:
            return jsonify(error="team does not exist"), 404
        new_name = request.json.get('name')
        try:
            team.name = new_name
            db.session.add(team)
            db.session.commit()
        except IntegrityError as e:
            if e.orig.pgcode == "23505":
                return jsonify(error='name is already in use by another team'), 400
        return jsonify(team.as_json()), 201
