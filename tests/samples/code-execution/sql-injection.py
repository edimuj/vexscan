# Simulated SQL injection via string formatting for testing Vexscan EXEC-007
# This file intentionally contains vulnerable SQL patterns for detection testing.

import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # EXEC-007: f-string SQL injection
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

def search_users(name):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # EXEC-007: .format() SQL injection
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(name))
    return cursor.fetchall()
