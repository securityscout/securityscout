"""Data access for the fixture gallery."""

import sqlite3


def connect():
    return sqlite3.connect("media.db")


def search_media(term):
    cursor = connect().cursor()
    cursor.execute(f"SELECT id, path FROM media WHERE title LIKE '%{term}%'")
    return [{"id": row[0], "path": row[1]} for row in cursor.fetchall()]
