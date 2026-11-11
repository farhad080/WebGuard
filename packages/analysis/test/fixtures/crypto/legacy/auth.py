# Python service with MD5 password hashing (pattern rule) and a harmless file checksum.
import hashlib


def store_password(user, password):
    user.password_hash = hashlib.md5(password.encode()).hexdigest()


def file_checksum(data):
    return hashlib.md5(data).hexdigest()
