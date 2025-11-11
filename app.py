from flask import Flask, request, redirect, url_for, session
import base64
import time
import json
import os
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Serverless upload folder
app.config['UPLOAD_FOLDER'] = "/tmp/uploaded_keys"
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def get_private_key():
    pem_filename = session.get("pem_file")
    if not pem_filename:
        raise ValueError("No private key uploaded yet.")
    
    key_path = os.path.join(app.config['UPLOAD_FOLDER'], pem_filename)
    with open(key_path, "r") as key_file:
        return RSA.import_key(key_file.read())


def render_html(filename, **context):
    """Simple template renderer for root HTML files."""
    with open(filename, "r") as f:
        html = f.read()
    for key, value in context.items():
        html = html.replace(f"{{{{ {key} }}}}", str(value))
    return html


@app.route("/", methods=["GET", "POST"])
def upload_key():
    if request.method == "POST":
        uploaded_file = request.files.get("private_key")
        if not uploaded_file or uploaded_file.filename == "":
            return render_html("upload_key.html", error="Please select a valid .pem file.")
        
        key_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
        uploaded_file.save(key_path)
        session["pem_file"] = uploaded_file.filename
        return redirect(url_for("choose_mode"))
    
    return render_html("upload_key.html", error="")


@app.route("/mode")
def choose_mode():
    if "pem_file" not in session:
        return redirect(url_for("upload_key"))
    return render_html("choose_mode.html")


@app.route("/sign-without", methods=["GET", "POST"])
def sign_without():
    if "pem_file" not in session:
        return redirect(url_for("upload_key"))

    if request.method == "POST":
        timestamp = str(int(time.time()))
        try:
            private_key = get_private_key()
        except Exception as e:
            return render_html("sign_without.html", error=str(e), timestamp="", signing_string="", signature="")

        signing_string = timestamp.encode("utf-8")
        hash_obj = SHA256.new(signing_string)
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        signature_base64 = base64.b64encode(signature).decode("utf-8")

        return render_html("sign_without.html",
                           error="",
                           timestamp=timestamp,
                           signing_string=timestamp,
                           signature=signature_base64)

    return render_html("sign_without.html", error="", timestamp="", signing_string="", signature="")


@app.route("/sign-with", methods=["GET", "POST"])
def sign_with():
    if "pem_file" not in session:
        return redirect(url_for("upload_key"))

    payload_str = ""
    timestamp = ""

    if request.method == "POST":
        payload_str = request.form.get("payload", "").strip()
        timestamp = request.form.get("timestamp", "").strip()

        if not timestamp:
            timestamp = str(int(time.time()))

        try:
            payload = json.loads(payload_str)
        except Exception:
            return render_html("sign_with.html",
                               error="Invalid JSON payload",
                               payload=payload_str,
                               timestamp=timestamp,
                               signing_string="",
                               signature="")

        try:
            private_key = get_private_key()
        except Exception as e:
            return render_html("sign_with.html",
                               error=str(e),
                               payload=payload_str,
                               timestamp=timestamp,
                               signing_string="",
                               signature="")

        payload_canonical = json.dumps(payload, separators=(",", ":"))
        data_bytes = (payload_canonical + timestamp).encode("utf-8")

        hash_obj = SHA256.new(data_bytes)
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        signature_base64 = base64.b64encode(signature).decode("utf-8")

        return render_html("sign_with.html",
                           error="",
                           payload=payload_str,
                           timestamp=timestamp,
                           signing_string=payload_canonical + timestamp,
                           signature=signature_base64)

    return render_html("sign_with.html",
                       error="",
                       payload=payload_str,
                       timestamp=timestamp,
                       signing_string="",
                       signature="")
