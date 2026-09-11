"""HTTP surface of the fixture gallery."""

from flask import Flask, jsonify, request

from app.db import search_media

app = Flask(__name__)


@app.get("/api/search")
def search():
    term = request.args.get("q", "")
    return jsonify(search_media(term))


@app.get("/api/albums/<album_id>")
def album(album_id):
    return jsonify({"id": album_id})
