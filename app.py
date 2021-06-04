from config import app
from api.routes.home import home_api
from api.routes.login import login_api
from api.routes.mood import mood_api
from api.routes.user import user_api


if __name__ == '__main__':
    # register api endpoints
    app.register_blueprint(home_api)
    app.register_blueprint(login_api)
    app.register_blueprint(mood_api)
    app.register_blueprint(user_api)
    app.run(debug=True)
