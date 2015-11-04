from flask.ext.script import Manager
from flask.ext.migrate import Migrate, MigrateCommand

from webapp import application as app
from webapp import model

db = model.db
migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command('db', MigrateCommand)

db.session.commit()

if __name__ == '__main__':
    manager.run()
