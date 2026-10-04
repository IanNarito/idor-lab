import base64
import hashlib
import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, g

app = Flask(__name__)
app.secret_key = "super_insecure_secret_key_for_idor_lab"
DATABASE = "lab.db"

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT UNIQUE,
                username TEXT UNIQUE,
                password TEXT,
                role TEXT
            )
        ''')

        # Lab 1: Numeric Invoices
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS invoices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT,
                amount TEXT,
                details TEXT
            )
        ''')

        # Lab 2: Encoded Receipts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_code TEXT UNIQUE,
                user_id INTEGER,
                item TEXT,
                billing_info TEXT
            )
        ''')

        # Lab 3: Hashed Tokens (Confidential Notes)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                hash_token TEXT UNIQUE,
                title TEXT,
                secret_content TEXT
            )
        ''')

        # Lab 4: UUID Protected Documents
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS confidential_docs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                doc_uuid TEXT UNIQUE,
                owner_username TEXT,
                title TEXT,
                payload TEXT
            )
        ''')

        # Seed data
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            # Seed Users
            victim_uuid = str(uuid.uuid4())
            cursor.execute("INSERT INTO users (uuid, username, password, role) VALUES (?, 'victim', 'victim123', 'admin')", (victim_uuid,))
            cursor.execute("INSERT INTO users (uuid, username, password, role) VALUES (?, 'student', 'student123', 'user')", (str(uuid.uuid4()),))

            # Seed Lab 1: Sequential IDs
            cursor.execute("INSERT INTO invoices (id, user_id, title, amount, details) VALUES (101, 1, 'Victim Executive Payroll', '$14,500.00', 'Confidential salary disbursement for user 1 (Admin/Victim)')")
            cursor.execute("INSERT INTO invoices (id, user_id, title, amount, details) VALUES (102, 2, 'Student Tuition Fee Receipt', '$250.00', 'Standard laboratory enrollment invoice for student')")

            # Seed Lab 2: Base64 Encoded (ID: 501 -> NTAx, 502 -> NTAy)
            code_victim = base64.b64encode(b"501").decode()
            code_student = base64.b64encode(b"502").decode()
            cursor.execute("INSERT INTO receipts (receipt_code, user_id, item, billing_info) VALUES (?, 1, 'Enterprise Server Rack', 'Card: 4111-XXXX-XXXX-9999 (Victim)')", (code_victim,))
            cursor.execute("INSERT INTO receipts (receipt_code, user_id, item, billing_info) VALUES (?, 2, 'Mechanical Keyboard', 'Card: 5424-XXXX-XXXX-1111 (Student)')", (code_student,))

            # Seed Lab 3: MD5 of sequential IDs (md5('1') = c4ca4238..., md5('2') = c81e728d...)
            hash_victim = hashlib.md5(b"1").hexdigest()
            hash_student = hashlib.md5(b"2").hexdigest()
            cursor.execute("INSERT INTO notes (user_id, hash_token, title, secret_content) VALUES (1, ?, 'Executive Password Backup', 'FLAG{MD5_HASHES_ARE_REVERSIBLE_VIA_RAINBOW}')", (hash_victim,))
            cursor.execute("INSERT INTO notes (user_id, hash_token, title, secret_content) VALUES (2, ?, 'Student Study Routine', 'Review Kali Linux commands and Burp Suite basics.')", (hash_student,))

            # Seed Lab 4: Static Victim Document with unpredictable UUID
            doc_uuid = str(uuid.uuid4())
            cursor.execute("INSERT INTO confidential_docs (doc_uuid, owner_username, title, payload) VALUES (?, 'victim', 'Internal Penetration Report', 'FLAG{UNPREDICTABLE_IDS_ARE_NOT_AUTHORIZATION}')", (doc_uuid,))

            db.commit()

# --- Auth Routes ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["uuid"] = user["uuid"]
            session["role"] = user["role"]
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid username or password.")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        new_uuid = str(uuid.uuid4())
        db = get_db()
        try:
            db.execute("INSERT INTO users (uuid, username, password, role) VALUES (?, ?, ?, 'user')", (new_uuid, username, password))
            db.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Username already registered.")
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# --- Lab 1: Basic Numeric IDOR ---
@app.route("/lab1")
def lab1():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    # Defaults to student invoice (id=102) if not specified
    invoice_id = request.args.get("id", default=102, type=int)
    db = get_db()
    # VULNERABILITY: Direct query using user-supplied ID without session['user_id'] authorization check
    invoice = db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    
    return render_template("lab1.html", invoice=invoice, current_id=invoice_id)

# --- Lab 2: Encoded ID (Base64) ---
@app.route("/lab2")
def lab2():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    ref = request.args.get("ref", default="NTAy")  # NTAy = 502 (student)
    db = get_db()
    # VULNERABILITY: Fetches receipt directly by base64 code without verifying ownership
    receipt = db.execute("SELECT * FROM receipts WHERE receipt_code = ?", (ref,)).fetchone()
    
    return render_template("lab2.html", receipt=receipt, current_ref=ref)

# --- Lab 3: Hashed ID (MD5) ---
@app.route("/lab3")
def lab3():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    # Default is MD5 of "2" (student's ID)
    default_token = hashlib.md5(b"2").hexdigest()
    token = request.args.get("token", default=default_token)
    db = get_db()
    # VULNERABILITY: Using a predictable hash (md5 of user_id) as an object identifier without auth check
    note = db.execute("SELECT * FROM notes WHERE hash_token = ?", (token,)).fetchone()
    
    return render_template("lab3.html", note=note, current_token=token)

# --- Lab 4: Unpredictable UUID (2-Account Multi-User IDOR) ---
@app.route("/lab4", methods=["GET", "POST"])
def lab4():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    db = get_db()
    
    # Creation endpoint for user's own documents
    if request.method == "POST":
        title = request.form.get("title")
        payload = request.form.get("payload")
        doc_uuid = str(uuid.uuid4())
        db.execute("INSERT INTO confidential_docs (doc_uuid, owner_username, title, payload) VALUES (?, ?, ?, ?)",
                   (doc_uuid, session["username"], title, payload))
        db.commit()
        return redirect(url_for("lab4"))

    # Viewing a document via query parameter
    requested_uuid = request.args.get("doc_id")
    selected_doc = None
    if requested_uuid:
        # VULNERABILITY: Retrieves document purely by UUID; ignores session['username']
        selected_doc = db.execute("SELECT * FROM confidential_docs WHERE doc_uuid = ?", (requested_uuid,)).fetchone()

    # List only documents belonging to the currently logged in user on the main panel
    my_docs = db.execute("SELECT * FROM confidential_docs WHERE owner_username = ?", (session["username"],)).fetchall()
    
    return render_template("lab4.html", my_docs=my_docs, selected_doc=selected_doc, requested_uuid=requested_uuid)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)