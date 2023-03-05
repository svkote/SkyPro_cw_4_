from flask import abort

import jwt
import datetime
import calendar

from helpers.constants import SECRET, ALGO
from service.user import UserService


class AuthService:
    def __init__(self, user_service: UserService):
        self.user_service = user_service

    def generate_token(self, email, password, is_refresh=False):
        user = self.user_service.get_user_by_email(email)

        if user is None:
            abort(404)

        if not is_refresh:
            if not self.user_service.compare_password(user.password, password):
                abort(404)

        data = {
            'email': email,
            'role': user.role,
        }

        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data["exp"] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(data, SECRET, algorithm=ALGO)

        days30 = datetime.datetime.utcnow() + datetime.timedelta(days=30)
        data["exp"] = calendar.timegm(days30.timetuple())
        refresh_token = jwt.encode(data, SECRET, algorithm=ALGO)

        return {
            'access_token': access_token,
            'refresh_token': refresh_token
        }

    def refresh_token(self, token):
        data = jwt.decode(token, SECRET, algorithms=[ALGO])
        email = data["email"]
        user = self.user_service.get_user_by_email(email)
        if user is None:
            return False
        return self.generate_token(email, user.password, is_refresh=True)
