import sqlite3

from flask import g


def get_conn():
    if "conn" not in g:
        g.conn = sqlite3.connect("clinic.db")
    return g.conn
