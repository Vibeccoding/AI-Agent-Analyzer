import json
import os

def load_users():
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except:
        return {"admin": "password"}

def validate_user(username, password):
    users = load_users()
    return users.get(username) == password