"""Payments Service — invoice & receipt downloads."""
import os
from flask import Flask, request, send_file, redirect, render_template_string

app = Flask(__name__)

RECEIPTS_DIR = "/var/app/receipts"


@app.route("/receipts/download")
def download_receipt():
    filename = request.args.get("file")
    path = os.path.join(RECEIPTS_DIR, filename)
    return send_file(path)


@app.route("/invoices/open")
def open_invoice():
    invoice_path = request.args.get("path")
    with open(invoice_path, "r") as f:
        return f.read()


@app.route("/login/continue")
def login_continue():
    next_url = request.args.get("next")
    return redirect(next_url)


@app.route("/search")
def search_receipts():
    query = request.args.get("q", "")
    template = "<h3>Results for: " + query + "</h3>"
    return render_template_string(template)
