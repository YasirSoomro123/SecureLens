import os
import uuid
import shutil
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from config import Config
from scanner.engine import ScanEngine
from scanner.injection import InjectionScanner
from scanner.xss import XSSScanner
from scanner.hardcoded_secrets import HardcodedSecretsScanner
from scanner.weak_crypto import WeakCryptoScanner
from scanner.misconfiguration import MisconfigurationScanner
from scanner.sensitive_data import SensitiveDataScanner

app = Flask(__name__)
app.config.from_object(Config)

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

reports_store = {}


def get_engine():
    engine = ScanEngine()
    engine.register_scanner(InjectionScanner())
    engine.register_scanner(XSSScanner())
    engine.register_scanner(HardcodedSecretsScanner())
    engine.register_scanner(WeakCryptoScanner())
    engine.register_scanner(MisconfigurationScanner())
    engine.register_scanner(SensitiveDataScanner())
    return engine


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in Config.ALLOWED_EXTENSIONS


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan_code():
    if "files" not in request.files and "folder" not in request.files:
        return jsonify({"error": "No files uploaded"}), 400

    engine = get_engine()
    temp_dir = os.path.join(app.config["UPLOAD_FOLDER"], str(uuid.uuid4())[:8])
    os.makedirs(temp_dir, exist_ok=True)

    try:
        files = request.files.getlist("files")
        folder_files = request.files.getlist("folder")
        all_files = files + folder_files

        if not all_files or all(f.filename == "" for f in all_files):
            return jsonify({"error": "No files selected"}), 400

        saved_count = 0
        for file in all_files:
            if file and file.filename:
                filename = secure_filename(file.filename)
                if not filename:
                    filename = f"file_{saved_count}"
                file.save(os.path.join(temp_dir, filename))
                saved_count += 1

        if saved_count == 0:
            return jsonify({"error": "No valid files to scan"}), 400

        result = engine.scan_directory(temp_dir)
        reports_store[result.scan_id] = result

        return jsonify(result.to_dict())

    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


@app.route("/scan-paste", methods=["POST"])
def scan_pasted_code():
    data = request.get_json()
    if not data or "code" not in data:
        return jsonify({"error": "No code provided"}), 400

    code = data["code"]
    language = data.get("language", "py")
    filename = data.get("filename", f"pasted_code.{language}")

    engine = get_engine()
    temp_dir = os.path.join(app.config["UPLOAD_FOLDER"], str(uuid.uuid4())[:8])
    os.makedirs(temp_dir, exist_ok=True)

    try:
        file_path = os.path.join(temp_dir, filename)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(code)

        result = engine.scan_single_file(file_path, filename)
        reports_store[result.scan_id] = result

        return jsonify(result.to_dict())

    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


@app.route("/report/<scan_id>")
def download_report(scan_id):
    result = reports_store.get(scan_id)
    if not result:
        return jsonify({"error": "Report not found"}), 404

    report_path = os.path.join(app.config["UPLOAD_FOLDER"], f"report_{scan_id}.html")
    html_content = render_template("report.html", result=result.to_dict())
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return send_file(report_path, as_attachment=True, download_name=f"security_report_{scan_id}.html")


@app.route("/history/<scan_id>")
def get_report(scan_id):
    result = reports_store.get(scan_id)
    if not result:
        return jsonify({"error": "Report not found"}), 404
    return jsonify(result.to_dict())


@app.route("/about")
def about():
    return render_template("about.html")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
