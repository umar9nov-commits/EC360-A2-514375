import hashlib
import json
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer

USERS = {}


def register_user(email, password):
    if not isinstance(email, str) or "@" not in email:
        raise ValueError("A valid email is required.")
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("Password must contain at least 8 characters.")

    email = email.strip().lower()
    if email in USERS:
        raise ValueError("Email is already registered.")

    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 600000
    )

    USERS[email] = {
        "salt": salt.hex(),
        "password_hash": password_hash.hex(),
    }
    return {"email": email, "message": "Registration successful"}


class RegistrationHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/register":
            self.send_error(404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("Request must contain a JSON object.")
            result = register_user(
                data.get("email"), data.get("password")
            )
            status = 201
        except (ValueError, TypeError):
            result = {"error": "Invalid registration or duplicate email."}
            status = 400

        body = json.dumps(result).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print("Registration endpoint: http://localhost:8000/register")
    HTTPServer(("127.0.0.1", 8000), RegistrationHandler).serve_forever()
