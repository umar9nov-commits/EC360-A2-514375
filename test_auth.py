import hashlib
import unittest
from auth_service import USERS, register_user


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        USERS.clear()

    def test_successful_registration(self):
        result = register_user("umar@example.com", "Password123")
        self.assertEqual(result["email"], "umar@example.com")
        self.assertIn("umar@example.com", USERS)

    def test_password_hash_and_salt(self):
        password = "Password123"
        register_user("umar@example.com", password)
        record = USERS["umar@example.com"]

        expected_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(record["salt"]),
            600000,
        ).hex()

        self.assertEqual(record["password_hash"], expected_hash)
        self.assertNotEqual(record["password_hash"], password)

    def test_same_password_uses_different_salts(self):
        register_user("first@example.com", "Password123")
        register_user("second@example.com", "Password123")
        self.assertNotEqual(
            USERS["first@example.com"]["password_hash"],
            USERS["second@example.com"]["password_hash"],
        )

    def test_duplicate_email_rejected(self):
        register_user("umar@example.com", "Password123")
        with self.assertRaises(ValueError):
            register_user("UMAR@example.com", "Password123")

    def test_invalid_email_rejected(self):
        with self.assertRaises(ValueError):
            register_user("invalid-email", "Password123")
        self.assertEqual(USERS, {})

    def test_short_password_rejected(self):
        with self.assertRaises(ValueError):
            register_user("umar@example.com", "123")
        self.assertEqual(USERS, {})


if __name__ == "__main__":
    unittest.main()
