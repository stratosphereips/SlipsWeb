from pathlib import Path

from flask import Flask, jsonify, render_template, current_app

from dashboard_data import get_dashboard_payload

BASE_DIR = Path(__file__).resolve().parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/dashboard")
def dashboard_api():
    try:
        data = get_dashboard_payload()
        return jsonify(data)
    except Exception as exc:  # pragma: no cover - defensive logging
        current_app.logger.exception("Failed to build dashboard payload: %s", exc)
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
