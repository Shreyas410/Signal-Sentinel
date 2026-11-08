"""Database access layer."""
import sqlite3

DB_PATH = "t_life.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def get_user_by_id(user_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s" % user_id)
    return cur.fetchone()


def run_lookup_query(query):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()


def search_users(name_filter):
    conn = get_connection()
    cur = conn.cursor()
    sql = "SELECT id, name, email FROM users WHERE name LIKE '%{}%'".format(name_filter)
    cur.execute(sql)
    return cur.fetchall()
