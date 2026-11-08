"""Concrete, applicable code fixes for each finding in the demo repos.

Keyed by (repo_id, file, line) -> {"original": <current text at that
location>, "fixed": <replacement text>}. "original" is checked against
the live file before writing, so a fix only applies if the file still
matches what the scanner saw — if someone already hand-edited the file,
the apply is refused rather than corrupting it.
"""

FIXES = {
    "core-api": {
        ("app.py", 13): {
            "original": 'STRIPE_API_KEY = "admin_51Hc8x2EXAMPLEKEYDONTUSE00000000"',
            "fixed": 'STRIPE_API_KEY = os.environ["STRIPE_API_KEY"]',
        },
        ("app.py", 14): {
            "original": 'ADMIN_TOKEN = "admin_super_secret_token_2024"',
            "fixed": 'ADMIN_TOKEN = os.environ["ADMIN_TOKEN"]',
        },
        ("app.py", 20): {
            "original": '    query = "SELECT * FROM users WHERE id = \'" + user_id + "\'"\n    return jsonify(run_lookup_query(query))',
            "fixed": '    query = "SELECT * FROM users WHERE id = ?"\n    return jsonify(run_lookup_query(query, (user_id,)))',
        },
        ("app.py", 38): {
            "original": '    output = subprocess.check_output(cmd, shell=True)',
            "fixed": '    output = subprocess.check_output(["convert_report.sh", filename, "--format", fmt])',
        },
        ("app.py", 45): {
            "original": '    session_obj = pickle.loads(blob)',
            "fixed": '    session_obj = json.loads(blob)',
        },
        ("app.py", 51): {
            "original": '    url = request.json["callback_url"]\n    resp = requests.get(url, verify=False, timeout=5)',
            "fixed": '    url = request.json["callback_url"]\n    if not is_allowed_webhook_host(url):\n        return jsonify({"error": "host not allowed"}), 400\n    resp = requests.get(url, timeout=5)',
        },
        ("app.py", 65): {
            "original": '    app.run(host="0.0.0.0", debug=True)',
            "fixed": '    app.run(host="0.0.0.0", debug=False)',
        },
        ("app.py", 59): {
            "original": '    if token == ADMIN_TOKEN:',
            "fixed": '    if hmac.compare_digest(token, ADMIN_TOKEN):',
        },
        ("auth.py", 10): {
            "original": '    return hashlib.md5(password.encode()).hexdigest()',
            "fixed": '    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()',
        },
        ("auth.py", 28): {
            "original": '    return jwt.decode(token, JWT_SECRET, options={"verify_signature": False})',
            "fixed": '    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])',
        },
        ("db.py", 14): {
            "original": '    cur.execute("SELECT * FROM users WHERE id = %s" % user_id)',
            "fixed": '    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        },
        ("db.py", 28): {
            "original": '    sql = "SELECT id, name, email FROM users WHERE name LIKE \'%{}%\'".format(name_filter)\n    cur.execute(sql)',
            "fixed": '    sql = "SELECT id, name, email FROM users WHERE name LIKE ?"\n    cur.execute(sql, ("%" + name_filter + "%",))',
        },
        ("utils.py", 8): {
            "original": '        return yaml.load(f.read())  # no Loader pinned',
            "fixed": '        return yaml.safe_load(f.read())',
        },
        ("utils.py", 17): {
            "original": '    return eval(expr, {"__builtins__": {}}, context)',
            "fixed": '    return ast.literal_eval(expr)  # only parses literals, never executes code',
        },
        ("utils.py", 21): {
            "original": '    os.system("rm -rf " + path)',
            "fixed": '    shutil.rmtree(path)',
        },
        ("requirements.txt", 2): {
            "original": "pyyaml==5.3.1",
            "fixed": "pyyaml==6.0.1",
        },
        ("requirements.txt", 3): {
            "original": "requests==2.19.1",
            "fixed": "requests==2.32.3",
        },
        ("requirements.txt", 4): {
            "original": "pyjwt==1.7.1",
            "fixed": "pyjwt==2.8.0",
        },
    },
    "payments-service": {
        ("payments.py", 6): {
            "original": 'INTERNAL_API_KEY = "admin_9fQeXamplePaymentsKeyDoNotUse0000"',
            "fixed": 'INTERNAL_API_KEY = os.environ["INTERNAL_API_KEY"]',
        },
        ("payments.py", 13): {
            "original": '    if provided_key == INTERNAL_API_KEY:',
            "fixed": '    if hmac.compare_digest(provided_key, INTERNAL_API_KEY):',
        },
        ("payments.py", 21): {
            "original": '    if signature == WEBHOOK_SECRET:',
            "fixed": '    if hmac.compare_digest(signature, WEBHOOK_SECRET):',
        },
        ("downloads.py", 12): {
            "original": '    filename = request.args.get("file")\n    path = os.path.join(RECEIPTS_DIR, filename)',
            "fixed": '    filename = request.args.get("file")\n    safe_name = os.path.basename(filename)\n    path = os.path.realpath(os.path.join(RECEIPTS_DIR, safe_name))\n    if not path.startswith(os.path.realpath(RECEIPTS_DIR)):\n        return "forbidden", 403',
        },
        ("downloads.py", 19): {
            "original": '    invoice_path = request.args.get("path")\n    with open(invoice_path, "r") as f:',
            "fixed": '    safe_name = os.path.basename(request.args.get("path", ""))\n    invoice_path = os.path.realpath(os.path.join(RECEIPTS_DIR, safe_name))\n    if not invoice_path.startswith(os.path.realpath(RECEIPTS_DIR)):\n        return "forbidden", 403\n    with open(invoice_path, "r") as f:',
        },
        ("downloads.py", 26): {
            "original": '    next_url = request.args.get("next")\n    return redirect(next_url)',
            "fixed": '    next_url = request.args.get("next", "/")\n    if not next_url.startswith("/"):\n        next_url = "/"\n    return redirect(next_url)',
        },
        ("downloads.py", 33): {
            "original": '    template = "<h3>Results for: " + query + "</h3>"\n    return render_template_string(template)',
            "fixed": '    return render_template_string("<h3>Results for: {{ q }}</h3>", q=query)',
        },
    },
}


def get_fix(repo_id, file, line):
    return FIXES.get(repo_id, {}).get((file, line))
