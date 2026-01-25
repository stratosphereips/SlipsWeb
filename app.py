from pathlib import Path

from flask import Flask, jsonify, render_template, current_app, request

from dashboard_data import clear_alerts_collection, get_dashboard_payload

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
        limit = request.args.get("limit")
        next_token = request.args.get("next")
        try:
            limit_value = int(limit) if limit is not None else None
        except ValueError:
            limit_value = None
        data = get_dashboard_payload(limit=limit_value, next_token=next_token)
        return jsonify(data)
    except Exception as exc:  # pragma: no cover - defensive logging
        current_app.logger.exception("Failed to build dashboard payload: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/alerts/clear", methods=["POST"])
def clear_alerts():
    try:
        data = clear_alerts_collection()
        return jsonify(data)
    except Exception as exc:  # pragma: no cover - defensive logging
        current_app.logger.exception("Failed to clear TAXII data: %s", exc)
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
