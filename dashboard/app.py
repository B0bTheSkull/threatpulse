"""Flask web dashboard for ThreatPulse."""
import json
import logging
import os
import sys
import threading
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, request, jsonify
import lookup as lookup_module

logger = logging.getLogger(__name__)

app = Flask(__name__)
HISTORY_FILE = Path(__file__).parent.parent / "lookup_history.json"
_HISTORY_LOCK = threading.Lock()


def save_history(ioc, ioc_type, result):
    # Serialize the read-modify-write so concurrent requests can't corrupt the file.
    with _HISTORY_LOCK:
        history = []
        if HISTORY_FILE.exists():
            try:
                history = json.loads(HISTORY_FILE.read_text())
            except Exception:
                logger.warning("Could not read history file %s; starting fresh", HISTORY_FILE, exc_info=True)
        history.insert(0, {
            "timestamp": datetime.now().isoformat(),
            "ioc": ioc,
            "type": ioc_type,
            "threat_level": result.get("threat_level", "UNKNOWN")
        })
        history = history[:100]  # Keep last 100
        HISTORY_FILE.write_text(json.dumps(history))


def get_history():
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text())
        except Exception:
            logger.warning("Could not read history file %s", HISTORY_FILE, exc_info=True)
    return []


@app.route("/")
def index():
    history = get_history()
    return render_template("index.html", history=history)


@app.route("/lookup", methods=["POST"])
def do_lookup():
    ioc = request.form.get("ioc", "").strip()
    ioc_type = request.form.get("type", "ip").strip()

    if not ioc:
        return jsonify({"error": "No IOC provided"}), 400

    result = lookup_module.lookup(ioc, ioc_type)
    save_history(ioc, ioc_type, result)
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
