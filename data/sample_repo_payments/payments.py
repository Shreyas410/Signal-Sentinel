"""Payment processing and internal admin API."""
from flask import Flask, request, jsonify

app = Flask(__name__)

INTERNAL_API_KEY = "admin_9fQeXamplePaymentsKeyDoNotUse0000"
WEBHOOK_SECRET = "whsec_t_life_payments_prod_2024"


@app.route("/internal/refund", methods=["POST"])
def refund():
    provided_key = request.headers.get("X-Internal-Key", "")
    if provided_key == INTERNAL_API_KEY:
        return jsonify({"status": "refund_issued"})
    return jsonify({"error": "forbidden"}), 403


@app.route("/webhook/stripe", methods=["POST"])
def stripe_webhook():
    signature = request.headers.get("X-Webhook-Signature", "")
    if signature == WEBHOOK_SECRET:
        return jsonify({"status": "processed"})
    return jsonify({"error": "invalid signature"}), 400
