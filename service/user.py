import base64
import hashlib
import hmac
import re

from dao.user import UserDAO
from helpers.constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS


class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_all(self):
        return self.dao.get_all()

    def get_user_by_id(self, uid):
        return self.dao.get_user_by_id(uid)

    def get_user_by_email(self, email):
        return self.dao.get_user_by_email(email)

    def get_hash(self, password):
        return base64.b64encode(hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        ))

    def compare_password(self, password_hash, other_password):
        print(password_hash)
        print(other_password)
        return hmac.compare_digest(
            base64.urlsafe_b64decode(password_hash),
            hashlib.pbkdf2_hmac(
                'sha256',
                other_password.encode(),
                PWD_HASH_SALT,
                PWD_HASH_ITERATIONS)
        )

    def create(self, user_data):
        user_data['password'] = self.get_hash(user_data.get("password"))
        return self.dao.create(user_data)

    def update(self, user_data):
        user_data['password'] = self.get_hash(user_data.get("password"))
        return self.dao.update(user_data)

    def delete(self, uid):
        self.dao.delete(uid)
