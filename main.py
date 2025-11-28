# For local testing:
# 1. Install MySQL and create a database/user:
#    CREATE DATABASE door_db;
#    CREATE USER 'testuser'@'localhost' IDENTIFIED BY 'testpass';
#    GRANT ALL PRIVILEGES ON door_db.* TO 'testuser'@'localhost';
# 2. Set SQLALCHEMY_DATABASE_URI to:
#    "mysql+pymysql://testuser:testpass@localhost:3306/door_db"
# 3. Run /dev/init_db once to initialize tables.

"""
app.py -- Dash + Flask admin portal with:
 - Azure AD login (MSAL)
 - MySQL (SQLAlchemy)
 - REST API for Raspberry Pi that validates API key and returns JWT
 - Admin UI to manage cards, access attributes/time windows, view logs

IMPORTANT:
 - Run behind HTTPS in production (Ngrok/dev only for local testing).
 - Store secrets in environment variables or a secrets manager.
 - Use a proper device onboarding flow for API keys (not included).
"""

import os
from urllib.parse import quote_plus
import json
import hashlib
import datetime
from functools import wraps

from flask import Flask, session, redirect, url_for, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
import msal
import jwt  # PyJWT
from werkzeug.security import generate_password_hash, check_password_hash

import dash
from dash import html, dcc, Dash, Input, Output, State, ctx, dash_table
import pandas as pd

DISABLE_AUTH = os.environ.get("DISABLE_AUTH", "false").lower() == "true"

# load required secrets (fail fast instead of using insecure defaults)
# load required secrets (with defaults for testing)
AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "AZURE_CLIENT_SECRET")
AZURE_TENANT_ID = os.environ.get("AZURE_TENANT_ID", "common")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-jwt-secret-change-in-production")

DB_USER = os.environ.get("MYSQL_USER", "admin_spark")
DB_PASS = quote_plus(os.environ.get("MYSQL_PASSWORD", "Spark1ETS"))  # quote special chars
DB_HOST = os.environ.get("MYSQL_HOST", "mysql-spark.mysql.database.azure.com")
DB_NAME = os.environ.get("MYSQL_DATABASE", "myconnector")
SQLALCHEMY_DATABASE_URI = os.environ.get(
    "SQLALCHEMY_DATABASE_URI",
    f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:3306/{DB_NAME}?ssl_ca=&ssl_verify_cert=true&ssl_verify_identity=true"
)

PI_TOKEN_EXP_MIN = int(os.environ.get("PI_TOKEN_EXP_MIN", "60"))
FRONTEND_BASE = os.environ.get("FRONTEND_BASE", "https://example.com")

AUTHORITY = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}"
SCOPE = ["User.Read"]
REDIRECT_PATH = "/getAToken"
REDIRECT_URI = FRONTEND_BASE + REDIRECT_PATH

# -----------------------
# Flask + DB + MSAL Setup
# -----------------------
server = Flask(__name__)
server.config["SECRET_KEY"] = SECRET_KEY
server.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
server.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False



import pymysql, os; 
try:
    conn = pymysql.connect(
        host=os.getenv("MYSQL_HOST", "mysql-spark.mysql.database.azure.com"),
        user=os.getenv("MYSQL_USER", "admin_spark"),
        password=os.getenv("MYSQL_PASSWORD", "Spark1ETS"),
        database=os.getenv("MYSQL_DATABASE", "myconnector"),  # Fixed from MYCONNECTOR
        port=int(os.getenv("MYSQL_PORT", "3306")),
        ssl={'ssl_mode': 'REQUIRED'},  # Added SSL requirement
        connect_timeout=3
    )
    print(f"✅ Connected to MySQL at {os.getenv('MYSQL_HOST', 'mysql-spark.mysql.database.azure.com')}")
    conn.close()
except Exception as e:
    print(f"❌ Could not connect to MySQL: {e}")

db = SQLAlchemy(server)

# -----------------------
# Database Models
# -----------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    oid = db.Column(db.String(128), unique=True)  # Azure object id
    email = db.Column(db.String(256), unique=True)
    name = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False)

class Card(db.Model):
    __tablename__ = "cards"
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.String(128), unique=True, nullable=False)  # e.g. RFID tag
    owner = db.Column(db.String(256))
    active = db.Column(db.Boolean, default=True)

class AccessRule(db.Model):
    __tablename__ = "access_rules"
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.String(128), db.ForeignKey("cards.card_id"), nullable=False)
    encre_id = db.Column(db.String(128), db.ForeignKey("encre_devices.encre_id"), nullable=True)
    access_from = db.Column(db.Time, nullable=True)
    access_to = db.Column(db.Time, nullable=True)
    attributes = db.Column(db.Text)

class AccessLog(db.Model):
    __tablename__ = "access_logs"
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.String(128))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    result = db.Column(db.String(64))  # e.g., "granted", "denied", "invalid_card"
    reason = db.Column(db.Text)

class ConnectionLog(db.Model):
    __tablename__ = "connection_logs"
    id = db.Column(db.Integer, primary_key=True)
    numTag = db.Column(db.String(128))
    tagEncre = db.Column(db.String(20))
    last_connection = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class PiDevice(db.Model):
    __tablename__ = "pi_devices"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(128), unique=True)
    api_key_hash = db.Column(db.String(256))  # hashed API key for device
    description = db.Column(db.String(256))
    enabled = db.Column(db.Boolean, default=True)

#DB Encre
class EncreDevice(db.Model):
    __tablename__ = "encre_devices"
    id = db.Column(db.Integer, primary_key=True)
    encre_id = db.Column(db.String(128), unique=True, nullable=False)
    encre_name = db.Column(db.String(256), unique=True, nullable=False)
    description = db.Column(db.Text)
    active = db.Column(db.Boolean, default=True)

# -----------------------
# Utility: create MSAL app
# -----------------------
def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        AZURE_CLIENT_ID, authority=authority or AUTHORITY,
        client_credential=AZURE_CLIENT_SECRET, token_cache=cache
    )

def _build_auth_url(scopes=None, state=None):
    msal_app = _build_msal_app()
    return msal_app.get_authorization_request_url(
        scopes or [],
        state=state or None,
        redirect_uri=REDIRECT_URI
    )

# -----------------------
# Flask Routes - Login
# -----------------------
@server.route("/login")
def login():
    session.clear()
    auth_url = _build_auth_url(scopes=SCOPE, state=None)
    return redirect(auth_url)

@server.route(REDIRECT_PATH)
def authorized():
    # Handles redirect from Azure AD
    code = request.args.get("code")
    if not code:
        return "No code provided by Azure", 400
    msal_app = _build_msal_app()
    result = msal_app.acquire_token_by_authorization_code(
        code,
        scopes=SCOPE,
        redirect_uri=REDIRECT_URI
    )
    if "error" in result:
        return f"Login failure: {result.get('error_description')}", 400

    # Store user info in session
    id_token_claims = result.get("id_token_claims")
    if not id_token_claims:
        return "No ID token claims", 400

    oid = id_token_claims.get("oid")
    preferred_username = id_token_claims.get("preferred_username") or id_token_claims.get("upn")
    name = id_token_claims.get("name") or preferred_username

    session["user"] = {
        "oid": oid,
        "email": preferred_username,
        "name": name
    }

    # ensure user exists in DB
    user = User.query.filter_by(oid=oid).first()
    if not user:
        # first time user -> not admin by default. Manually promote via DB or add logic.
        user = User(oid=oid, email=preferred_username, name=name, is_admin=False)
        db.session.add(user)
        db.session.commit()

    return redirect("/")

@server.route("/logout")
def logout():
    session.clear()
    return redirect(
        AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + FRONTEND_BASE
    )

# -----------------------
# Helper: require_login decorator
# -----------------------
def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if DISABLE_AUTH:
            # Mock user for dev/testing
            session["user"] = {
                "oid": "dev-user",
                "email": "dev@example.com",
                "name": "Dev User"
            }
        elif "user" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if DISABLE_AUTH:
            # In dev mode: ensure a dev-admin session and DB record, then allow
            session.setdefault("user", {"oid": "dev-admin", "email": "admin@example.com", "name": "Dev Admin"})
            usr = session.get("user")
            db_user = User.query.filter_by(oid=usr.get("oid")).first()
            if not db_user:
                db_user = User(
                    oid=usr.get("oid"),
                    email=usr.get("email"),
                    name=usr.get("name"),
                    is_admin=True
                )
                db.session.add(db_user)
                db.session.commit()
            return f(*args, **kwargs)

        # Normal (auth enabled) path: require signed in admin user
        usr = session.get("user")
        if not usr:
            return redirect("/login")
        db_user = User.query.filter_by(oid=usr.get("oid")).first()
        if not db_user or not db_user.is_admin:
            return "Forbidden: Admins only", 403
        return f(*args, **kwargs)
    return decorated

@server.route("/dev_login")
def dev_login():
    if not DISABLE_AUTH:
        return "Dev mode disabled", 403
    session["user"] = {
        "oid": "dev-admin",
        "email": "admin@example.com",
        "name": "Dev Admin"
    }
    # Create admin user if not exists
    db_user = User.query.filter_by(oid="dev-admin").first()
    if not db_user:
        db_user = User(
            oid="dev-admin",
            email="admin@example.com",
            name="Dev Admin",
            is_admin=True
        )
        db.session.add(db_user)
        db.session.commit()
    return redirect("/")



# -----------------------
# Helper: require_login decorator
# -----------------------
def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if DISABLE_AUTH:
            # Mock user for dev/testing
            session["user"] = {
                "oid": "dev-user",
                "email": "dev@example.com",
                "name": "Dev User"
            }
        elif "user" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


# -----------------------
# REST API for Raspberry Pi (device validation)
#
# Flow:
# 1) Pi authenticates with an API key (device-specific). Calls /api/pi/validate to get JWT token.
# 2) Pi uses JWT token on subsequent /api/pi/check_access or to send logs.
# -----------------------
def verify_device_api_key(device_id, api_key_plain):
    device = PiDevice.query.filter_by(device_id=device_id, enabled=True).first()
    if not device:
        return False
    # Compare hashed key
    return check_password_hash(device.api_key_hash, api_key_plain)



@server.route("/api/pi/validate", methods=["POST"])
def pi_validate():
    """
    POST payload: { "device_id": "...", "api_key": "..." }
    -> returns {"token": "<jwt>", "expires_at": "<iso>"}
    """
    data = request.json or {}
    device_id = data.get("device_id")
    api_key = data.get("api_key")
    if not device_id or not api_key:
        return jsonify({"error": "device_id and api_key required"}), 400

    if not verify_device_api_key(device_id, api_key):
        return jsonify({"error": "invalid_device_or_key"}), 401

    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(minutes=PI_TOKEN_EXP_MIN)
    payload = {
        "sub": device_id,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "type": "pi_device"
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token, "expires_at": exp.isoformat()})

def require_pi_jwt(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing_token"}), 401
        token = auth.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token_expired"}), 401
        except Exception as e:
            return jsonify({"error": "invalid_token", "detail": str(e)}), 401
        # attach device id to request context
        request.device_id = payload.get("sub")
        return f(*args, **kwargs)
    return decorated

@server.route("/api/pi/check_access", methods=["POST"])
@require_pi_jwt
def pi_check_access():
    """
    Pi posts { "card_id": "..." } with Authorization: Bearer <jwt>
    Server checks rules and returns granted/denied. Also logs access.
    """
    data = request.json or {}
    card_id = data.get("card_id")
    device_id = getattr(request, "device_id", "unknown")
    if not card_id:
        return jsonify({"error": "card_id required"}), 400

    card = Card.query.filter_by(card_id=card_id, active=True).first()
    now = datetime.datetime.utcnow()
    granted = False
    reason = "card_inactive_or_missing"
    if not card:
        reason = "invalid_card"
    else:
        # get rules
        rules = AccessRule.query.filter_by(card_id=card_id).all()
        if not rules:
            # default deny if no rules
            granted = False
            reason = "no_rules"
        else:
            # check if any rule allows now
            for r in rules:
                if r.access_from and r.access_to:
                    # compare only time-of-day
                    tnow = now.time()
                    if r.access_from <= tnow <= r.access_to:
                        granted = True
                        reason = "time_allowed"
                        break
                else:
                    # no time limits => allow
                    granted = True
                    reason = "allowed_no_time_limit"
                    break

    # log
    log = AccessLog(card_id=card_id, timestamp=now, result="granted" if granted else "denied", reason=reason)
    db.session.add(log)
    db.session.commit()

    return jsonify({"granted": granted, "reason": reason})

# Endpoint for Pi to send logs (optionally)
@server.route("/api/pi/send_log", methods=["POST"])
@require_pi_jwt
def pi_send_log():
    payload = request.json or {}
    card_id = payload.get("card_id")
    result = payload.get("result", "unknown")
    reason = payload.get("reason", "")
    log = AccessLog(card_id=card_id, timestamp=datetime.datetime.utcnow(), result=result, reason=reason)
    db.session.add(log)
    db.session.commit()
    return jsonify({"ok": True})

# -----------------------
# Admin REST endpoints used by the Dash UI (server-protected)
# -----------------------
@server.route("/api/admin/cards", methods=["GET", "POST", "DELETE"])
@require_admin
def admin_cards():
    if request.method == "GET":
        cards = Card.query.all()
        return jsonify([{"card_id": c.card_id, "owner": c.owner, "active": c.active} for c in cards])
    
    if request.method == "POST":
        data = request.json or {}
        card_id = data.get("card_id")
        owner = data.get("owner")
        if not card_id:
            return jsonify({"error": "card_id required"}), 400
        if Card.query.filter_by(card_id=card_id).first():
            return jsonify({"error": "card_exists"}), 400
        
        # Create card
        c = Card(card_id=card_id, owner=owner)
        db.session.add(c)
        
        # Create default deny rule (no access)
        default_rule = AccessRule(
            card_id=card_id,
            access_from=None,
            access_to=None,
            door_id=None,
            attributes=json.dumps({"default": "no_access"})
        )
        db.session.add(default_rule)
        db.session.commit()
        return jsonify({"ok": True})
    
    if request.method == "DELETE":
        data = request.json or {}
        card_id = data.get("card_id")
        c = Card.query.filter_by(card_id=card_id).first()
        if not c:
            return jsonify({"error": "not_found"}), 404
        
        # Delete associated rules
        AccessRule.query.filter_by(card_id=card_id).delete()
        db.session.delete(c)
        db.session.commit()
        return jsonify({"ok": True})

@server.route("/api/admin/access_rule", methods=["POST", "PUT", "DELETE"])
@require_admin
def admin_access_rule():
    if request.method == "POST":
        data = request.json or {}
        card_id = data.get("card_id")
        encre_id = data.get("encre_id")
        access_from = data.get("access_from")
        access_to = data.get("access_to")
        attributes = data.get("attributes", {})
        
        if not card_id:
            return jsonify({"error": "card_id required"}), 400
        
        atime_from = None
        atime_to = None
        if access_from:
            atime_from = datetime.datetime.strptime(access_from, "%H:%M").time()
        if access_to:
            atime_to = datetime.datetime.strptime(access_to, "%H:%M").time()
        
        ar = AccessRule(
            card_id=card_id,
            encre_id=encre_id if encre_id else None,
            access_from=atime_from,
            access_to=atime_to,
            attributes=json.dumps(attributes)
        )
        db.session.add(ar)
        db.session.commit()
        return jsonify({"ok": True})
    
    if request.method == "PUT":
        data = request.json or {}
        rule_id = data.get("rule_id")
        rule = AccessRule.query.filter_by(id=rule_id).first()
        if not rule:
            return jsonify({"error": "not_found"}), 404
        
        if "encre_id" in data:
            rule.encre_id = data["encre_id"]
        if "access_from" in data and data["access_from"]:
            rule.access_from = datetime.datetime.strptime(data["access_from"], "%H:%M").time()
        if "access_to" in data and data["access_to"]:
            rule.access_to = datetime.datetime.strptime(data["access_to"], "%H:%M").time()
        if "attributes" in data:
            rule.attributes = json.dumps(data["attributes"])
        
        db.session.commit()
        return jsonify({"ok": True})
    
    if request.method == "DELETE":
        data = request.json or {}
        rule_id = data.get("rule_id")
        r = AccessRule.query.filter_by(id=rule_id).first()
        if not r:
            return jsonify({"error": "not_found"}), 404
        db.session.delete(r)
        db.session.commit()
        return jsonify({"ok": True})

@server.route("/api/admin/logs", methods=["GET"])
@require_admin
def admin_logs():
    # simple filters
    card_id = request.args.get("card_id")
    limit = min(int(request.args.get("limit", "200")), 2000)
    query = AccessLog.query
    if card_id:
        query = query.filter_by(card_id=card_id)
    logs = query.order_by(AccessLog.timestamp.desc()).limit(limit).all()
    return jsonify([{"card_id": l.card_id, "timestamp": l.timestamp.isoformat(), "result": l.result, "reason": l.reason} for l in logs])

#----------------------------------------------------------------
#----------------------------------------------------------------
#----------------------------------------------------------------
#----------------------------------------------------------------
#----------------------------------------------------------------
#----------------------------------------------------------------
@server.route("/api/admin/logs_connection", methods=["GET"])
@require_admin
def admin_logs_connection():
    # Get all connection logs
    logs = ConnectionLog.query.order_by(ConnectionLog.last_connection.desc()).all()
    
    return jsonify([{
        "numTag": log.numTag, 
        "tagEncre": log.tagEncre, 
        "last_connection": log.last_connection.isoformat()
    } for log in logs])

@server.route("/api/admin/encres", methods=["GET", "POST", "PUT", "DELETE"])
@require_admin
def admin_encres():
    if request.method == "GET":
        encres = EncreDevice.query.all()
        return jsonify([{
            "encre_id": d.encre_id, 
            "encre_name": d.encre_name, 
            "description": d.description,
            "active": d.active
        } for d in encres])
    
    if request.method == "POST":
        data = request.json or {}
        encre_id = data.get("encre_id")
        encre_name = data.get("encre_name")
        if not encre_id or not encre_name:
            return jsonify({"error": "encre_id and encre_name required"}), 400
        if EncreDevice.query.filter_by(encre_id=encre_id).first():
            return jsonify({"error": "encre_exists"}), 400
        d = EncreDevice(
            encre_id=encre_id, 
            encre_name=encre_name,
            description=data.get("description", "")
        )
        db.session.add(d)
        db.session.commit()
        return jsonify({"ok": True})
    
    if request.method == "PUT":
        data = request.json or {}
        encre_id = data.get("encre_id")
        encre = EncreDevice.query.filter_by(encre_id=encre_id).first()
        if not encre:
            return jsonify({"error": "not_found"}), 404
        if "encre_name" in data:
            encre.encre_name = data["encre_name"]
        if "description" in data:
            encre.description = data["description"]
        if "active" in data:
            encre.active = data["active"]
        db.session.commit()
        return jsonify({"ok": True})
    
    if request.method == "DELETE":
        data = request.json or {}
        encre_id = data.get("encre_id")
        encre = EncreDevice.query.filter_by(encre_id=encre_id).first()
        if not encre:
            return jsonify({"error": "not_found"}), 404
        db.session.delete(encre)
        db.session.commit()
        return jsonify({"ok": True})

@server.route("/api/admin/card_rules/<card_id>", methods=["GET"])
@require_admin
def get_card_rules(card_id):
    rules = AccessRule.query.filter_by(card_id=card_id).all()
    return jsonify([{
        "id": r.id,
        "card_id": r.card_id,
        "door_id": r.door_id,
        "access_from": r.access_from.isoformat() if r.access_from else "",
        "access_to": r.access_to.isoformat() if r.access_to else "",
        "attributes": r.attributes
    } for r in rules])


# -----------------------
# Dash App (UI)
# -----------------------
app = Dash(__name__, server=server, url_base_pathname="/", suppress_callback_exceptions=True)
app.title = 'Spark door access admin'
app._faicon = ("assets/sparkmicro_rgb.ico")

# Simple top layout: header with login/logout, sections to manage cards, rules, logs
app.layout = html.Div([
    html.Div(id="header", children=[
        html.H2("Door Access Admin Portal"),
        html.Div(id="user-info"),
        html.A("Login (Azure)", href="/login", id="login-link"),
        html.A("Logout", href="/logout", id="logout-link", style={"marginRight": "10px"})
    ], style={"display": "flex", "alignItems": "center", "gap": "10px"}),

    dcc.Tabs(id="tabs", children=[
        dcc.Tab(label="Cards", value="cards"),
        dcc.Tab(label="Encres", value="encres"),
        dcc.Tab(label="Access Rules", value="rules"),
        dcc.Tab(label="Logs", value="logs"),
        dcc.Tab(label="Connection Logs", value="logs_connection"),
        dcc.Tab(label="Pi Devices (Admin)", value="pi")
    ], value="cards"),
    html.Div(id="tab-content"),
    
    # Modal for editing rules
    html.Div(id="edit-rules-modal", style={"display": "none"}, children=[
        html.Div(style={
            "position": "fixed", "top": "50%", "left": "50%",
            "transform": "translate(-50%, -50%)",
            "backgroundColor": "white", "padding": "20px",
            "border": "1px solid black", "zIndex": "1000",
            "minWidth": "500px"
        }, children=[
            html.H3(id="modal-title"),
            html.Div(id="modal-content"),
            html.Button("Close", id="close-modal-btn")
        ])
    ])
])

# -----------------------
# Callbacks: populate header + tab content (server-side fetch)
# -----------------------
@app.callback(
    Output("user-info", "children"),
    [Input("tabs", "value")]
)
def update_user_info(_):
    usr = session.get("user")
    if not usr:
        return html.Span("Not signed in")
    db_user = User.query.filter_by(oid=usr.get("oid")).first()
    name = usr.get("name") or usr.get("email")
    admin_tag = " (admin)" if db_user and db_user.is_admin else ""
    return html.Span(f"Signed in as {name}{admin_tag}")

@app.callback(Output("tab-content", "children"), [Input("tabs", "value")])
def render_tab(tab):
    if tab == "cards":
        cards = Card.query.all()
        df = pd.DataFrame([{"card_id": c.card_id, "owner": c.owner, "active": c.active} for c in cards])
        return html.Div([
            html.H3("Cards"),
            dash_table.DataTable(
                id="cards-table",
                columns=[{"name": c, "id": c} for c in df.columns],
                data=df.to_dict("records"),
                row_selectable="single",
            ),
            html.Div([
                dcc.Input(id="new-card-id", placeholder="card id (tag)", type="text"),
                dcc.Input(id="new-card-owner", placeholder="owner", type="text"),
                html.Button("Add Card", id="add-card-btn"),
                html.Button("Edit Rules", id="edit-rules-btn", style={"marginLeft": "10px"}),
            ]),
            html.Button("Delete Selected Card", id="delete-card-btn"),
            html.Div(id="cards-msg")
        ])
    
    if tab == "encres":
        encres = EncreDevice.query.all()
        df = pd.DataFrame([{
            "encre_id": d.encre_id,
            "encre_name": d.encre_name,
            "description": d.description,
            "active": d.active
        } for d in encres])
        return html.Div([
            html.H3("Encres / Doors"),
            dash_table.DataTable(
                id="encres-table",
                columns=[{"name": c, "id": c} for c in df.columns],
                data=df.to_dict("records"),
                row_selectable="single",
                editable=True
            ),
            html.Div([
                dcc.Input(id="new-encre-id", placeholder="encre id (unique)", type="text"),
                dcc.Input(id="new-encre-name", placeholder="encre name", type="text"),
                dcc.Input(id="new-encre-desc", placeholder="description", type="text"),
                html.Button("Add Encre", id="add-encre-btn")
            ]),
            html.Button("Delete Selected Encre", id="delete-encre-btn"),
            html.Div(id="encres-msg")
        ])
    
    if tab == "rules":
        rules = AccessRule.query.all()
        encres = EncreDevice.query.all()
        encre_names = {d.encre_id: d.encre_name for d in encres}
        
        df = pd.DataFrame([{
            "id": r.id,
            "card_id": r.card_id,
            "encre": encre_names.get(r.encre_id, r.encre_id or "All"),
            "access_from": r.access_from.isoformat() if r.access_from else "",
            "access_to": r.access_to.isoformat() if r.access_to else "",
            "attributes": r.attributes
        } for r in rules])
        
        return html.Div([
            html.H3("Access Rules"),
            dash_table.DataTable(
                id="rules-table",
                columns=[{"name": c, "id": c} for c in df.columns],
                data=df.to_dict("records"),
                row_selectable="single",
            ),
            html.Div([
                dcc.Input(id="rule-card-id", placeholder="card id", type="text"),
                html.Label("Select Encre/Door:"),
                dcc.RadioItems(
                    id="rule-encre-select",
                    options=[{"label": "All Encres", "value": ""}] + 
                            [{"label": d.encre_name, "value": d.encre_id} for d in encres],
                    value=""
                ),
                dcc.Input(id="rule-from", placeholder="HH:MM", type="text"),
                dcc.Input(id="rule-to", placeholder="HH:MM", type="text"),
                dcc.Input(id="rule-attrs", placeholder='attributes JSON', type="text"),
                html.Button("Add Rule", id="add-rule-btn")
            ]),
            html.Button("Delete Selected Rule", id="delete-rule-btn"),
            html.Div(id="rules-msg")
        ])
    
    if tab == "logs":
        logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(200).all()
        df = pd.DataFrame([{"card_id": l.card_id, "timestamp": l.timestamp.isoformat(), "result": l.result, "reason": l.reason} for l in logs])
        return html.Div([
            html.H3("Access Logs"),
            dash_table.DataTable(
                id="logs-table",
                columns=[{"name": c, "id": c} for c in df.columns],
                data=df.to_dict("records"),
                page_size=20
            ),
            html.Button("Refresh", id="refresh-logs")
        ])
    
    if tab == "logs_connection":
        logs = ConnectionLog.query.order_by(ConnectionLog.last_connection.desc()).all()
        data = [{
            "numTag": l.numTag,
            "tagEncre": l.tagEncre,
            "last_connection": l.last_connection.isoformat() if l.last_connection else ""
        } for l in logs]
        df = pd.DataFrame(data, columns=["numTag", "tagEncre", "last_connection"])
        return html.Div([
             html.H3("Connection Logs"),
             dash_table.DataTable(
                 id="connection-table",
                 columns=[{"name": c, "id": c} for c in df.columns],
                 data=df.to_dict("records"),
                 page_size=20
             ),
             html.Button("Refresh", id="refresh-connection-logs")
        ])
    
    if tab == "pi":
        devices = PiDevice.query.all()
        df = pd.DataFrame([{"device_id": d.device_id, "description": d.description, "enabled": d.enabled} for d in devices])
        return html.Div([
            html.H3("Raspberry Pi Devices"),
            dash_table.DataTable(
                id="pi-table",
                columns=[{"name": c, "id": c} for c in df.columns],
                data=df.to_dict("records"),
                row_selectable="single"
            ),
            html.Div([
                dcc.Input(id="new-pi-id", placeholder="device id", type="text"),
                dcc.Input(id="new-pi-desc", placeholder="description", type="text"),
                dcc.Input(id="new-pi-api-key", placeholder="api key (plaintext)", type="text"),
                html.Button("Add Pi Device", id="add-pi-btn")
            ]),
            html.Button("Toggle Selected Device Enabled", id="toggle-pi-btn"),
            html.Div(id="pi-msg")
        ])

# -----------------------
# Callbacks: Add/Delete card and rules (client -> server)
# -----------------------
@app.callback(
    Output("cards-msg", "children"),
    [Input("add-card-btn", "n_clicks"), Input("delete-card-btn", "n_clicks")],
    [State("new-card-id", "value"), State("new-card-owner", "value"), State("cards-table", "selected_rows"), State("cards-table", "data")]
)
def handle_cards(add_click, delete_click, new_card_id, new_card_owner, selected_rows, table_data):
    triggered = ctx.triggered_id
    if triggered == "add-card-btn":
        if not new_card_id:
            return "card_id required"
        # server call
        res = server.test_client().post("/api/admin/cards", json={"card_id": new_card_id, "owner": new_card_owner})
        if res.status_code == 200:
            return "Card added"
        else:
            return f"Error: {res.get_json()}"
    if triggered == "delete-card-btn":
        if not selected_rows:
            return "Select a row first"
        row = table_data[selected_rows[0]]
        card_id = row["card_id"]
        res = server.test_client().delete("/api/admin/cards", json={"card_id": card_id})
        if res.status_code == 200:
            return "Card deleted"
        else:
            return f"Error: {res.get_json()}"
    return ""

@app.callback(
    Output("rules-msg", "children"),
    [Input("add-rule-btn", "n_clicks"), Input("delete-rule-btn", "n_clicks")],
    [State("rule-card-id", "value"), State("rule-encre-select", "value"),
     State("rule-from", "value"), State("rule-to", "value"), State("rule-attrs", "value"),
     State("rules-table", "selected_rows"), State("rules-table", "data")]
)
def handle_rules(add_click, delete_click, card_id, encre_id, rfrom, rto, rattrs, selected_rows, table_data):
    triggered = ctx.triggered_id
    if triggered == "add-rule-btn":
        if not card_id:
            return "card_id required"
        try:
            attrs = json.loads(rattrs) if rattrs else {}
        except Exception as e:
            return f"Invalid attributes JSON: {e}"
        res = server.test_client().post("/api/admin/access_rule", json={
            "card_id": card_id,
            "encre_id": encre_id if encre_id else None,
            "access_from": rfrom,
            "access_to": rto,
            "attributes": attrs
        })
        if res.status_code == 200:
            return "Rule added"
        else:
            return f"Error: {res.get_json()}"
    if triggered == "delete-rule-btn":
        if not selected_rows:
            return "Select a rule first"
        row = table_data[selected_rows[0]]
        rule_id = row["id"]
        res = server.test_client().delete("/api/admin/access_rule", json={"rule_id": rule_id})
        if res.status_code == 200:
            return "Rule deleted"
        else:
            return f"Error: {res.get_json()}"
    return ""

@app.callback(
    Output("pi-msg", "children"),
    [Input("add-pi-btn", "n_clicks"), Input("toggle-pi-btn", "n_clicks")],
    [State("new-pi-id", "value"), State("new-pi-desc", "value"), State("new-pi-api-key", "value"),
     State("pi-table", "selected_rows"), State("pi-table", "data")]
)
def handle_pi(add_click, toggle_click, new_id, new_desc, new_api_key, selected_rows, table_data):
    triggered = ctx.triggered_id
    if triggered == "add-pi-btn":
        if not new_id or not new_api_key:
            return "device_id and api_key required"
        # Hash key and insert
        if PiDevice.query.filter_by(device_id=new_id).first():
            return "device already exists"
        api_key_hash = generate_password_hash(new_api_key)
        d = PiDevice(device_id=new_id, api_key_hash=api_key_hash, description=new_desc)
        db.session.add(d)
        db.session.commit()
        return "Pi device added (store plaintext key securely on device!)"
    if triggered == "toggle-pi-btn":
        if not selected_rows:
            return "Select device row"
        row = table_data[selected_rows[0]]
        device_id = row["device_id"]
        d = PiDevice.query.filter_by(device_id=device_id).first()
        if not d:
            return "Device not found"
        d.enabled = not d.enabled
        db.session.commit()
        return f"Device {device_id} enabled={d.enabled}"
    return ""

@app.callback(
    Output("encres-msg", "children"),
    [Input("add-encre-btn", "n_clicks"), Input("delete-encre-btn", "n_clicks")],
    [State("new-encre-id", "value"), State("new-encre-name", "value"), 
     State("new-encre-desc", "value"), State("encres-table", "selected_rows"), 
     State("encres-table", "data")]
)
def handle_encres(add_click, delete_click, new_id, new_name, new_desc, selected_rows, table_data):
    triggered = ctx.triggered_id
    if triggered == "add-encre-btn":
        if not new_id or not new_name:
            return "encre_id and encre_name required"
        res = server.test_client().post("/api/admin/encres", json={
            "encre_id": new_id, 
            "encre_name": new_name,
            "description": new_desc or ""
        })
        if res.status_code == 200:
            return "Encre added"
        else:
            return f"Error: {res.get_json()}"
    if triggered == "delete-encre-btn":
        if not selected_rows:
            return "Select a row first"
        row = table_data[selected_rows[0]]
        encre_id = row["encre_id"]
        res = server.test_client().delete("/api/admin/encres", json={"encre_id": encre_id})
        if res.status_code == 200:
            return "Encre deleted"
        else:
            return f"Error: {res.get_json()}"
    return ""

@app.callback(
    [Output("edit-rules-modal", "style"), Output("modal-content", "children")],
    [Input("edit-rules-btn", "n_clicks"), Input("close-modal-btn", "n_clicks")],
    [State("cards-table", "selected_rows"), State("cards-table", "data")]
)
def handle_edit_rules(edit_click, close_click, selected_rows, table_data):
    triggered = ctx.triggered_id
    if triggered == "edit-rules-btn":
        if not selected_rows:
            return {"display": "none"}, []
        
        row = table_data[selected_rows[0]]
        card_id = row["card_id"]
        
        # Fetch rules for this card
        res = server.test_client().get(f"/api/admin/card_rules/{card_id}")
        rules = res.get_json()
        
        # Fetch available encres
        encres_res = server.test_client().get("/api/admin/encres")
        encres = encres_res.get_json()
        
        content = [
            html.H4(f"Rules for Card: {card_id}"),
            html.Div([
                html.Div([
                    html.P(f"Rule {r['id']}: Encre={r['encre_id'] or 'All'}, "
                           f"From={r['access_from']}, To={r['access_to']}"),
                    html.Button(f"Delete Rule {r['id']}", id={"type": "del-rule", "index": r['id']})
                ]) for r in rules
            ]),
            html.Hr(),
            html.H5("Add New Rule"),
            html.Label("Encre:"),
            dcc.RadioItems(
                id="modal-encre-select",
                options=[{"label": "All Encres", "value": ""}] + 
                        [{"label": d['encre_name'], "value": d['encre_id']} for d in encres],
                value=""
            ),
            dcc.Input(id="modal-from", placeholder="HH:MM", type="text"),
            dcc.Input(id="modal-to", placeholder="HH:MM", type="text"),
            html.Button("Add Rule", id="modal-add-rule-btn"),
            dcc.Store(id="modal-card-id", data=card_id)
        ]
        
        return {"display": "block"}, content
    
    if triggered == "close-modal-btn":
        return {"display": "none"}, []
    
    return {"display": "none"}, []

# -----------------------
# Initialize DB helper route (for dev only)
# -----------------------
@server.route("/dev/init_db")
def dev_init_db():
    # only allow on debug/dev
    if server.debug or os.environ.get("DEV_INIT") == "1":
        db.create_all()
        return "db initialized"
    return "disabled", 403

# -----------------------
# Run
# -----------------------

if __name__ == "__main__":
    # Safety: ensure redirect uri uses the right FRONTEND_BASE
    print("Starting Dash app. FRONTEND_BASE:", FRONTEND_BASE)
    server.run(host="0.0.0.0", port=8000, debug=True)
else:
    print("Dash app loaded as module.")
    with server.app_context():
        db.create_all()  # ensure tables exist
