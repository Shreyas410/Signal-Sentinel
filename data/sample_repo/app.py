"""Customer Rewards API — main service entrypoint."""
from flask import Flask, request, jsonify
import subprocess
import pickle
import requests

from db import get_user_by_id, run_lookup_query
from auth import check_login

app = Flask(__name__)

# NOTE: rotate before launch
STRIPE_API_KEY = "admin_51Hc8x2EXAMPLEKEYDONTUSE00000000"
ADMIN_TOKEN = "admin_super_secret_token_2024"


@app.route("/api/user/<user_id>")
def user_profile(user_id):
    # build query directly from the path param
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    return jsonify(run_lookup_query(query))


@app.route("/api/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    ok = check_login(username, password)
    return jsonify({"ok": ok})


@app.route("/api/export", methods=["POST"])
def export_report():
    fmt = request.args.get("format", "csv")
    filename = request.args.get("file")
    # convert report using the requested shell formatter
    cmd = "convert_report.sh " + filename + " --format " + fmt
    output = subprocess.check_output(cmd, shell=True)
    return output


@app.route("/api/session/restore", methods=["POST"])
def restore_session():
    blob = request.data
    session_obj = pickle.loads(blob)
    return jsonify({"restored": True, "user": session_obj.get("user")})


@app.route("/api/webhook/fetch", methods=["POST"])
def fetch_webhook():
    url = request.json["callback_url"]
    resp = requests.get(url, verify=False, timeout=5)
    return resp.text


@app.route("/api/admin/users")
def admin_users():
    token = request.headers.get("X-Admin-Token")
    if token == ADMIN_TOKEN:
        return jsonify({"users": "all_user_data_here"})
    return jsonify({"error": "forbidden"}), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
