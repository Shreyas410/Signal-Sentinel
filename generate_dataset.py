"""Generates a synthetic labeled dataset of scam vs legitimate messages,
then scores it with scam_shield.analyze_message to report precision/recall."""
import json
import os
import random

import scam_shield

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_PATH = os.path.join(BASE_DIR, "data", "synthetic_messages.json")

random.seed(42)

SCAM_TEMPLATES = [
    "USPS: Your package could not be delivered. Pay a $1.99 redelivery fee within 24 hours at http://usps-redelivery.top/track",
    "Congratulations! You've been selected for a $500 carrier loyalty reward. Claim your prize now at http://carrier-rewards-claim.xyz",
    "Your Bank of America account has unusual activity and will be suspended. Verify your account immediately: http://bofa-secure-verify.click",
    "IRS NOTICE: You owe back taxes. Pay now with a gift card or face an arrest warrant. Call 1-800-555-0199.",
    "Your Amazon order couldn't be charged. Update your payment info within 24 hours or your order will be cancelled: http://amazon-billing.work/update",
    "FedEx: We attempted delivery but need a small customs fee processed. Act fast: http://fedex-fee.info/pay",
    "Final notice: your Apple ID has been locked due to suspicious activity. Confirm your identity now: http://apple-id-confirm.tk",
    "You have an unpaid toll from last week. Pay now to avoid late fees and legal action: http://ezpass-unpaid.loan/pay",
    "PayPal: We noticed unusual activity. Your account will be suspended in 24 hours unless you verify: http://paypal-verify-now.xyz",
    "Social Security Administration: your SSN has been suspended due to suspicious activity. Call immediately to avoid arrest.",
    "Carrier Billing: your bill payment failed. Pay immediately via Zelle to avoid service suspension: http://carrier-billing-pay.click",
    "Your package is held at customs. Pay a small processing fee now: http://usps-customs.top/release",
]

LEGIT_TEMPLATES = [
    "Hey, are we still meeting for lunch at 1pm tomorrow?",
    "Your Amazon order #112-7788342 has shipped and will arrive Thursday.",
    "Reminder: your dentist appointment is scheduled for Monday at 10am.",
    "Your carrier: Your bill of $70.00 was paid successfully on Nov 1. Thank you!",
    "Mom: Don't forget to pick up milk on your way home.",
    "Your Uber is arriving in 3 minutes. Driver: John, Toyota Camry.",
    "Your verification code for signing in is 482193. Don't share this code with anyone.",
    "FedEx: Your package was delivered to your front porch at 2:14pm today.",
    "Hi team, the meeting has been moved to 3pm in conference room B.",
    "Your flight AA 2051 departs at 6:45am from Gate C12. Check in online now.",
    "Thanks for your payment! Your latest statement is ready to view in the app.",
    "Hey, loved the photos from the trip, can you send me a few more?",
]


def generate(n_each=130):
    rows = []
    for i in range(n_each):
        tpl = random.choice(SCAM_TEMPLATES)
        rows.append({"id": f"scam-{i}", "text": tpl, "label": "scam"})
    for i in range(n_each):
        tpl = random.choice(LEGIT_TEMPLATES)
        rows.append({"id": f"legit-{i}", "text": tpl, "label": "legit"})
    random.shuffle(rows)
    return rows


def main():
    rows = generate(130)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)

    tp = fp = tn = fn = 0
    patterns = scam_shield.load_scam_patterns(approved_only=True)
    for row in rows:
        result = scam_shield.analyze_message(row["text"], patterns=patterns)
        predicted_scam = result["risk"] in ("high", "medium")
        actual_scam = row["label"] == "scam"
        if predicted_scam and actual_scam:
            tp += 1
        elif predicted_scam and not actual_scam:
            fp += 1
        elif not predicted_scam and not actual_scam:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    accuracy = (tp + tn) / len(rows)

    metrics = {
        "dataset_size": len(rows),
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "accuracy": round(accuracy, 3),
    }
    with open(os.path.join(BASE_DIR, "data", "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
