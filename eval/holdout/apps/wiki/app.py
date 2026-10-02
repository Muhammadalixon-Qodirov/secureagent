import os
import sqlite3

from flask import Flask, abort, g, jsonify, request

app = Flask(__name__)
PAGES = os.path.realpath("/srv/wiki/pages")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect("wiki.db")
    return g.db


def page_path(slug):
    full = os.path.realpath(os.path.join(PAGES, slug + ".md"))
    if os.path.commonpath([full, PAGES]) != PAGES:
        abort(404)
    return full


@app.get("/wiki/<path:slug>")
def page(slug):
    with open(page_path(slug), encoding="utf-8") as fh:
        return fh.read()


@app.get("/wiki/<path:slug>/history")
def history(slug):
    with open(os.path.join(PAGES, ".history", slug + ".log"), encoding="utf-8") as fh:
        return fh.read()


@app.post("/wiki/tags")
def add_tags():
    page_slug = request.form["page"]
    tags = request.form["tags"].split(",")
    script = ";".join(f"INSERT INTO tags(page, tag) VALUES ('{page_slug}', '{t.strip()}')" for t in tags)
    get_db().executescript(script)
    return "", 204


@app.get("/wiki-search")
def search():
    q = request.args.get("q", "")
    rows = get_db().execute("SELECT slug FROM pages WHERE body LIKE ?", (f"%{q}%",)).fetchall()
    return jsonify([r[0] for r in rows])
