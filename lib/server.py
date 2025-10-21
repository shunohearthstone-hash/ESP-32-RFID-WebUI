# server.py
from flask import Flask, request, jsonify, g, render_template, send_file
import sqlite3, time, io, os
try:
    from flask_cors import CORS
except Exception:
    # If flask_cors isn't available, provide a no-op CORS to keep the app working.
    def CORS(app, *args, **kwargs):
        return None
from pybloom_live import ScalableBloomFilter

DB_PATH = "cards.db"
BLOOM_PATH = "bloom.bin"

app = Flask(__name__, template_folder="templates")
CORS(app)

# ---------- Global State ----------
last_scanned = None
enroll_mode = None  # "grant" | "revoke" | None

# ---------- DATABASE ----------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS cards(
            uid TEXT PRIMARY KEY,
            authorized INTEGER DEFAULT 1,
            added_at INTEGER,
            deleted_at INTEGER DEFAULT NULL
        );
    """)
    db.commit()

@app.before_first_request
def startup(): init_db()

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db: db.close()

# ---------- BLOOM FILTER ----------
def build_bloom():
    db = get_db()
    uids = [r[0] for r in db.execute("SELECT uid FROM cards WHERE authorized=1 AND deleted_at IS NULL")]
    bf = ScalableBloomFilter(mode=ScalableBloomFilter.SMALL_SET_GROWTH)
    for u in uids:
        bf.add(u)
    with open(BLOOM_PATH, "wb") as f:
        f.write(bf.bitarray.tobytes())

@app.route("/api/bloom", methods=["GET"])
def get_bloom():
    if not os.path.exists(BLOOM_PATH):
        build_bloom()
    return send_file(BLOOM_PATH, mimetype="application/octet-stream")

# ---------- API ----------
@app.route("/api/cards", methods=["GET"])
def list_cards():
    db = get_db()
    rows = [dict(r) for r in db.execute("SELECT uid, authorized, added_at FROM cards WHERE deleted_at IS NULL")]
    return jsonify(rows)

@app.route("/api/cards", methods=["POST"])
def add_card():
    data = request.get_json(force=True)
    uid = data.get("uid")
    auth = 1 if data.get("authorized", True) else 0
    now = int(time.time())
    if not uid:
        return jsonify({"error": "uid required"}), 400
    db = get_db()
    db.execute("""
        INSERT INTO cards(uid,authorized,added_at,deleted_at)
        VALUES(?,?,?,NULL)
        ON CONFLICT(uid) DO UPDATE SET
            authorized=excluded.authorized,
            deleted_at=NULL,
            added_at=excluded.added_at;
    """,(uid,auth,now))
    db.commit()
    build_bloom()
    return jsonify({"ok":True,"uid":uid}),201

@app.route("/api/cards/<uid>", methods=["DELETE"])
def delete_card(uid):
    db = get_db()
    db.execute("UPDATE cards SET deleted_at=? WHERE uid=?", (int(time.time()), uid))
    db.commit()
    build_bloom()
    return jsonify({"ok":True,"uid":uid})

@app.route("/api/cards/<uid>", methods=["PATCH"])
def update_card(uid):
    data = request.get_json(force=True)
    if "authorized" not in data:
        return jsonify({"error": "authorized field required"}), 400
    auth = 1 if data["authorized"] else 0
    db = get_db()
    db.execute("UPDATE cards SET authorized=? WHERE uid=?", (auth, uid))
    db.commit()
    build_bloom()
    return jsonify({"ok":True,"uid":uid,"authorized":auth})

@app.route("/api/cards/<uid>", methods=["GET"])
def get_card(uid):
    db = get_db()
    r = db.execute("SELECT * FROM cards WHERE uid=?", (uid,)).fetchone()
    if not r or r["deleted_at"]:
        return jsonify({"exists":False}),404
    return jsonify({"exists":True,"authorized":bool(r["authorized"])})

# ---------- ENROLLMENT FEATURE ----------

@app.route("/api/last_scan", methods=["POST"])
def last_scan():
    """Called by ESP32 when a card is scanned."""
    global last_scanned, enroll_mode
    data = request.get_json(force=True)
    uid = data.get("uid")
    if not uid:
        return jsonify({"error": "uid required"}), 400
    last_scanned = uid

    # If we are in enroll mode, act now:
    if enroll_mode in ("grant", "revoke"):
        db = get_db()
        auth = 1 if enroll_mode == "grant" else 0
        now = int(time.time())
        db.execute("""
            INSERT INTO cards(uid,authorized,added_at,deleted_at)
            VALUES(?,?,?,NULL)
            ON CONFLICT(uid) DO UPDATE SET
                authorized=excluded.authorized,
                deleted_at=NULL;
        """,(uid,auth,now))
        db.commit()
        build_bloom()
        enroll_mode = None  # reset after one use
        return jsonify({"ok":True,"enrolled":True,"mode":auth,"uid":uid})
    return jsonify({"ok":True,"uid":uid,"enrolled":False})

@app.route("/api/enroll", methods=["POST"])
def set_enroll_mode():
    """Enable enrollment mode for the next card scan."""
    global enroll_mode
    data = request.get_json(force=True)
    mode = data.get("mode")
    if mode not in ("grant","revoke",None):
        return jsonify({"error":"mode must be 'grant' or 'revoke'"}),400
    enroll_mode = mode
    return jsonify({"ok":True,"mode":enroll_mode})

@app.route("/api/status", methods=["GET"])
def status():
    """Report current enroll state and last scanned UID."""
    return jsonify({
        "last_scanned": last_scanned,
        "enroll_mode": enroll_mode
    })

# ---------- DASHBOARD ----------
@app.route("/")
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
