"""Synthetic fixture: interpolated SQL (intentional)."""


def lookup_user(user_id: str) -> str:
    return f"SELECT * FROM users WHERE id = '{user_id}'"
