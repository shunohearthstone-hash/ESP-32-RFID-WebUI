# server.py
from flask import Flask, request, jsonify, g, render_template, send_file
import sqlite3, time, io, os
import struct
import re
try:
    from flask_cors import CORS
except Exception:
    # If flask_cors isn't available, provide a no-op CORS to keep the app working.
    def CORS(app, *args, **kwargs):
        return None
#from pybloom_live import ScalableBloomFilter

DB_PATH = "cards.db"
BLOOM_PATH = "bloom.bin"

app = Flask(__name__, template_folder=".")
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
            uid TEXT PRIMARY KEY CHECK(length(uid) >= 8 AND length(uid) <= 20),
            authorized INTEGER DEFAULT 1,
            added_at INTEGER,
            deleted_at INTEGER DEFAULT NULL,
            card_id INTEGER UNIQUE,
            uid_hash TEXT
        );
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS counter (
            name TEXT PRIMARY KEY,
            value INTEGER
        );
    """)
    db.execute("INSERT OR IGNORE INTO counter(name, value) VALUES('next_card_id', 1)")
    db.commit()

def compute_uid_hash(uid):
    """Compute FNV-1a 64-bit hash matching ESP32 implementation."""
    normalized = uid.strip().upper()
    hash_val = 0xcbf29ce484222325  # FNV offset basis
    prime = 0x100000001b3          # FNV prime
    for char in normalized:
        hash_val ^= ord(char)
        hash_val = (hash_val * prime) & 0xFFFFFFFFFFFFFFFF  # Keep 64-bit
    return format(hash_val, '016X')  # Return as 16-char hex string

def ensure_db_initialized():
    if not hasattr(g, '_db_initialized'):
        init_db()
        g._db_initialized = True

@app.before_request
def before_request():
    ensure_db_initialized()

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db: db.close()

    
    # ----------  Tiny sync packet for ESP32 ----------
@app.route("/api/sync", methods=["GET"])
def get_sync_packet():
    db = get_db()
    # Get max card_id
    row = db.execute("SELECT COALESCE(MAX(card_id), 0) FROM cards WHERE card_id IS NOT NULL").fetchone()
    max_id = row[0]

    # Build compact bit array
    bits = bytearray((max_id + 7) // 8)
    cur = db.execute("SELECT card_id FROM cards WHERE authorized=1 AND deleted_at IS NULL AND card_id IS NOT NULL")
    for row in cur:
        idx = row[0]
        if idx >= 0:
            bits[idx // 8] |= (1 << (idx % 8))

    return jsonify({
        "max_id": max_id,
        "bits": bits.hex()       # tiny hex string, e.g. "ff03" for first 11 cards
    })

#---- Helpers ----
def assign_card_id(uid):
    db = get_db()
    # Get next ID and increment atomically
    db.execute("UPDATE counter SET value = value + 1 WHERE name = 'next_card_id'")
    next_id = db.execute("SELECT value FROM counter WHERE name = 'next_card_id'").fetchone()[0]
    db.execute("UPDATE cards SET card_id = ? WHERE uid = ? AND (card_id IS NULL OR card_id = 0)", (next_id - 1, uid))
    db.commit()
# ---------- API ----------
@app.route("/api/cards", methods=["GET"])
def list_cards():
    db = get_db()
    rows = [dict(r) for r in db.execute("SELECT uid, authorized, added_at, card_id, uid_hash FROM cards WHERE deleted_at IS NULL")]
    return jsonify(rows)

@app.route("/api/cards", methods=["POST"])
def add_card():
    data = request.get_json(force=True)
    uid = data.get("uid")
    auth = 1 if data.get("authorized", True) else 0
    now = int(time.time())
    if not uid:
        return jsonify({"error": "uid required"}), 400
    valid, error = validate_uid(uid)
    if not valid:
        return jsonify({"error": error}), 400
    uid_hash = compute_uid_hash(uid)
    db = get_db()
    db.execute("""
        INSERT INTO cards(uid,authorized,added_at,deleted_at,uid_hash)
        VALUES(?,?,?,NULL,?)
        ON CONFLICT(uid) DO UPDATE SET
            authorized=excluded.authorized,
            deleted_at=NULL,
            added_at=excluded.added_at,
            uid_hash=excluded.uid_hash;
    """,(uid,auth,now,uid_hash))
    assign_card_id(uid)
    db.commit()
    
    return jsonify({"ok":True,"uid":uid,"hash":uid_hash}),201

@app.route("/api/cards/<uid>", methods=["DELETE"])
def delete_card(uid):
    db = get_db()
    db.execute("UPDATE cards SET deleted_at=? WHERE uid=?", (int(time.time()), uid))
    db.commit()
   
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
   
    return jsonify({"ok":True,"uid":uid,"authorized":auth})

@app.route("/api/cards/<uid>", methods=["GET"])
def get_card(uid):
    db = get_db()
    r = db.execute("SELECT * FROM cards WHERE uid=?", (uid,)).fetchone()
    if not r or r["deleted_at"]:
        return jsonify({"exists":False}),404
    return jsonify({
        "exists":True,
        "authorized":bool(r["authorized"]),
        "card_id":r["card_id"] if r["card_id"] is not None else -1,
        "uid_hash":r["uid_hash"]
    })

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
    uid_hash = compute_uid_hash(uid)

    # If we are in enroll mode, act now:
    if enroll_mode in ("grant", "revoke"):
        db = get_db()
        auth = 1 if enroll_mode == "grant" else 0
        now = int(time.time())
        db.execute("""
            INSERT INTO cards(uid,authorized,added_at,deleted_at,uid_hash)
            VALUES(?,?,?,NULL,?)
            ON CONFLICT(uid) DO UPDATE SET
                authorized=excluded.authorized,
                deleted_at=NULL,
                uid_hash=excluded.uid_hash;
        """,(uid,auth,now,uid_hash))
        assign_card_id(uid)  # Ensure card_id is assigned
        db.commit()
        
        enroll_mode = None  # reset after one use
        return jsonify({"ok":True,"enrolled":True,"mode":auth,"uid":uid,"hash":uid_hash})
    return jsonify({"ok":True,"uid":uid,"enrolled":False,"hash":uid_hash})

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

# In server.py, add validation helper:
def validate_uid(uid):
    """Validate UID format: 8-20 uppercase hex chars."""
    if not uid or not isinstance(uid, str):
        return False, "UID required"
    if len(uid) < 8 or len(uid) > 20:
        return False, "UID must be 8-20 characters"
    if not re.match(r'^[0-9A-F]+$', uid.upper()):
        return False, "UID must be hexadecimal"
    return True, None

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
