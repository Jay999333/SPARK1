# main.py -- modified to:
# - remove Account Types tab
# - add account_type_rules endpoint for editing default rules (GET/PUT)
# - cards select account_type; non-custom cards inherit rules from account_type
# - remove Edit Rules modal and button from Cards tab
# - add Toggle Active button in Cards tab
# - add Toggle Active button in Encres tab
# - keep default account types in /dev/init_db (engineer, manager, visitor, custom)

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
AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "AZURE_CLIENT_SECRET")
AZURE_TENANT_ID = os.environ.get("AZURE_TENANT_ID", "common")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-jwt-secret-change-in-production")

DB_USER = os.environ.get("MYSQL_USER", "admin_spark")
DB_PASS = quote_plus(os.environ.get("MYSQL_PASSWORD", "Spark1ETS"))
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
        database=os.getenv("MYSQL_DATABASE", "myconnector"),
        port=int(os.getenv("MYSQL_PORT", "3306")),
        ssl={'ssl_mode': 'REQUIRED'},
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
    is_admin = db.Column(db.BOOLEAN, default=False)

# Account types are stored as default "access_rules" rows with card_id = NULL and account_type = '<type_name>'
# AccountType model removed; default rules are represented by AccessRule rows with card_id == None.

class Card(db.Model):
    __tablename__ = "cards"
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.String(128), unique=True, nullable=False)
    owner = db.Column(db.String(256))
    account_type = db.Column(db.String(128), nullable=True)
    active = db.Column(db.Boolean, default=True)

class AccessRule(db.Model):
    __tablename__ = "access_rules"
    id = db.Column(db.Integer, primary_key=True)
    # cards rules: card_id non-null. Default account-type rules: card_id is NULL and account_type is set
    card_id = db.Column(db.String(128), db.ForeignKey("cards.card_id"), nullable=True)
    account_type = db.Column(db.String(128), nullable=True)
    encre_id = db.Column(db.String(128), db.ForeignKey("encre_devices.encre_id"), nullable=True)
    access_from = db.Column(db.Time, nullable=True)
    access_to = db.Column(db.Time, nullable=True)


class ConnectionLog(db.Model):
    __tablename__ = "connection_logs"
    id = db.Column(db.Integer, primary_key=True)
    numTag = db.Column(db.String(128))
    tagEncre = db.Column(db.String(20))
    last_connection = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    result = db.Column(db.String(20))

class PiDevice(db.Model):
    __tablename__ = "pi_devices"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(128), unique=True)
    api_key_hash = db.Column(db.String(256))
    description = db.Column(db.String(256))
    enabled = db.Column(db.BOOLEAN, default=True)

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
# Login route
# -----------------------
@server.route("/login")
def login():
    session.clear()
    auth_url = _build_auth_url(scopes=SCOPE, state=None)
    return redirect(auth_url)

# Callback route
# -----------------------
# Handles response from Azure and gets token
@server.route(REDIRECT_PATH)
def authorized():
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

    user = User.query.filter_by(oid=oid).first()
    if not user:
        user = User(oid=oid, email=preferred_username, name=name, is_admin=False)
        db.session.add(user)
        db.session.commit()

    return redirect("/")

# Logout route
# -----------------------
@server.route("/logout")
def logout():
    session.clear()
    return redirect(
        AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + FRONTEND_BASE
    )

# -----------------------
# Helper decorators
# -----------------------
def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if DISABLE_AUTH:
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
            session.setdefault("user", {"oid": "dev-admin", 
                                        "email": "admin@example.com", 
                                        "name": "Dev Admin"
                                        })
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
# REST API for Raspberry Pi
# -----------------------
def verify_device_api_key(device_id, api_key_plain):
    device = PiDevice.query.filter_by(device_id=device_id, enabled=True).first()
    if not device:
        return False
    return check_password_hash(device.api_key_hash, api_key_plain)

@server.route("/api/pi/validate", methods=["POST"])
def pi_validate():
    data = request.json or {}
    device_id = data.get("device_id")
    api_key = data.get("api_key")
    if not device_id or not api_key:
        return jsonify({"error": "device_id and api_key required"}), 400

    if not verify_device_api_key(device_id, api_key):
        return jsonify({"error": "invalid_device_or_key"}), 401

    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(minutes=PI_TOKEN_EXP_MIN)
    payload = {"sub": device_id, "iat": int(now.timestamp()), "exp": int(exp.timestamp()), "type": "pi_device"}
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
        request.device_id = payload.get("sub")
        return f(*args, **kwargs)
    return decorated

@server.route("/api/pi/check_access", methods=["POST"])
@require_pi_jwt
def pi_check_access():
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
        rules = AccessRule.query.filter_by(card_id=card_id).all()
        if not rules:
            granted = False
            reason = "no_rules"
        else:
            for r in rules:
                if r.access_from and r.access_to:
                    tnow = now.time()
                    if r.access_from <= tnow <= r.access_to:
                        granted = True
                        reason = "time_allowed"
                        break
                else:
                    granted = True
                    reason = "allowed_no_time_limit"
                    break

    return jsonify({"granted": granted, "reason": reason})

@server.route("/api/pi/send_log", methods=["POST"])
@require_pi_jwt
def pi_send_log():
    
    return jsonify({"ok": True})

# -----------------------
# Admin REST endpoints used by Dash UI
# -----------------------
@server.route("/api/admin/cards", methods=["GET", "POST", "DELETE"])
@require_admin
def admin_cards():
    if request.method == "GET":
        cards = Card.query.all()
        result = []
        for c in cards:
            card_dict = {"card_id": c.card_id, "owner": c.owner, "active": c.active}
            try:
                card_dict["account_type"] = c.account_type or "visitor"
            except:
                card_dict["account_type"] = "visitor"
            result.append(card_dict)
        return jsonify(result)

    if request.method == "POST":
        data = request.json or {}
        card_id = data.get("card_id")
        owner = data.get("owner")
        account_type = data.get("account_type", "visitor")

        if not card_id:
            return jsonify({"error": "card_id required"}), 400

        if Card.query.filter_by(card_id=card_id).first():
            return jsonify({"error": "card_exists"}), 400

        try:
            c = Card(card_id=card_id, owner=owner, account_type=account_type)
            db.session.add(c)
            db.session.flush()

            # default deny rule if custom: keep explicit deny rule
            if account_type == "custom":
                default_rule = AccessRule(card_id=card_id, encre_id=None, access_from=None, access_to=None)
                db.session.add(default_rule)
                db.session.commit()
            else:
                # populate the new card's rules from default account-type rules stored in access_rules (card_id == NULL)
                defaults = AccessRule.query.filter_by(card_id=None, account_type=account_type).all()
                if not defaults:
                    # keep a deny rule if no defaults exist
                    db.session.add(AccessRule(card_id=card_id, encre_id=None, access_from=None, access_to=None))
                    db.session.commit()
                else:
                    # copy the defaults to specific card rows
                    for dr in defaults:
                        newr = AccessRule(card_id=card_id, account_type=None, encre_id=dr.encre_id, 
                                          access_from=dr.access_from, access_to=dr.access_to)
                        db.session.add(newr)
                    db.session.commit()

            return jsonify({"ok": True})

        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

    if request.method == "DELETE":
        data = request.json or {}
        card_id = data.get("card_id")
        c = Card.query.filter_by(card_id=card_id).first()
        if not c:
            return jsonify({"error": "not_found"}), 404

        try:
            AccessRule.query.filter_by(card_id=card_id).delete()
            db.session.delete(c)
            db.session.commit()
            return jsonify({"ok": True})
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

@server.route("/api/admin/cards/toggle", methods=["POST"])
@require_admin
def admin_cards_toggle():
    data = request.json or {}
    card_id = data.get("card_id")
    if not card_id:
        return jsonify({"error": "card_id required"}), 400
    c = Card.query.filter_by(card_id=card_id).first()
    if not c:
        return jsonify({"error": "not_found"}), 404
    c.active = not c.active
    db.session.commit()
    return jsonify({"ok": True, "active": c.active})

# NOTE: The original /api/admin/account_types route was removed (per request).
# New endpoint below exposes only the necessary functionality: GET the list of
# account types and PUT to update default_rules for a type (and propagate to cards).

@server.route("/api/admin/account_type_rules", methods=["GET", "PUT"])
@require_admin
def admin_account_type_rules():
    """
    GET => list available account types (type_name, default_rules)
    PUT => replace default rules for a given type_name:
        payload: { "type_name": "engineer", "default_rules": [ {"encre_id":"...", "access_from":"HH:MM", "access_to":"HH:MM"} ] }
    When updating default_rules, propagate to all cards with that account_type (except 'custom'):
        replace their rules with the default_rules
    """
    if request.method == "GET":
        # distinct account types derived from access_rules where card_id is NULL
        types = db.session.query(AccessRule.account_type).filter(AccessRule.card_id == None).distinct().all()
        out = []
        for t in types:
            type_name = t[0]
            rules = AccessRule.query.filter_by(card_id=None, account_type=type_name).all()
            out.append({
                "type_name": type_name,
                "default_rules": [
                    {"encre_id": r.encre_id, "access_from": r.access_from.isoformat() if r.access_from else "",
                      "access_to": r.access_to.isoformat() if r.access_to else ""} for r in rules
                ]
            })
        return jsonify(out)

    if request.method == "PUT":
        data = request.json or {}
        type_name = data.get("type_name")
        new_rules = data.get("default_rules")
        if not type_name:
            return jsonify({"error": "type_name required"}), 400
        if not isinstance(new_rules, list):
            return jsonify({"error": "default_rules must be a list"}), 400

        try:
            # remove existing default rules for account type
            AccessRule.query.filter_by(card_id=None, account_type=type_name).delete()
            # insert the new default rules as AccessRule rows with card_id == None
            for rr in new_rules:
                encre_id = rr.get("encre_id")
                af = rr.get("access_from")
                atime = rr.get("access_to")
                af_time = datetime.datetime.strptime(af, "%H:%M:%S").time() if af else None
                at_time = datetime.datetime.strptime(atime, "%H:%M:%S").time() if atime else None
                newr = AccessRule(card_id=None, account_type=type_name, encre_id=encre_id if encre_id else None, 
                                  access_from=af_time, access_to=at_time)
                db.session.add(newr)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

        # propagate to cards of this account type (except custom)
        if type_name != "custom":
            cards = Card.query.filter_by(account_type=type_name).all()
            for c in cards:
                try:
                    AccessRule.query.filter_by(card_id=c.card_id).delete()
                    # copy inserted default rules (those just created)
                    for rr in new_rules:
                        encre_id = rr.get("encre_id")
                        af = rr.get("access_from")
                        atime = rr.get("access_to")
                        af_time = datetime.datetime.strptime(af, "%H:%M:%S").time() if af else None
                        at_time = datetime.datetime.strptime(atime, "%H:%M:%S").time() if atime else None
                        newr = AccessRule(card_id=c.card_id, account_type=None, encre_id=encre_id if encre_id else None, 
                                          access_from=af_time, access_to=at_time)
                        db.session.add(newr)
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                    # continue with other cards
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

        if not card_id:
            return jsonify({"error": "card_id required"}), 400

        atime_from = None
        atime_to = None
        if access_from:
            atime_from = datetime.datetime.strptime(access_from, "%H:%M").time()
        if access_to:
            atime_to = datetime.datetime.strptime(access_to, "%H:%M").time()

        ar = AccessRule(card_id=card_id, encre_id=encre_id if encre_id else None, access_from=atime_from, access_to=atime_to)
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

@server.route("/api/admin/logs_connection", methods=["GET"])
@require_admin
def admin_logs_connection():
    logs = ConnectionLog.query.order_by(ConnectionLog.last_connection.desc()).all()
    return jsonify([{"numTag": log.numTag, "tagEncre": log.tagEncre, "last_connection": log.last_connection.isoformat(), 
                     "result": log.result} for log in logs])

@server.route("/api/admin/encres", methods=["GET", "POST", "PUT", "DELETE"])
@require_admin
def admin_encres():
    if request.method == "GET":
        encres = EncreDevice.query.all()
        return jsonify([{"encre_id": d.encre_id, "encre_name": d.encre_name, "description": d.description, 
                         "active": d.active} for d in encres])

    if request.method == "POST":
        data = request.json or {}
        encre_id = data.get("encre_id")
        encre_name = data.get("encre_name")
        if not encre_id or not encre_name:
            return jsonify({"error": "encre_id and encre_name required"}), 400
        if EncreDevice.query.filter_by(encre_id=encre_id).first():
            return jsonify({"error": "encre_exists"}), 400
        d = EncreDevice(encre_id=encre_id, encre_name=encre_name, description=data.get("description", ""))
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
        "account_type": r.account_type,
        "encre_id": r.encre_id,
        "access_from": r.access_from.isoformat() if r.access_from else "",
        "access_to": r.access_to.isoformat() if r.access_to else ""
    } for r in rules])

# -----------------------
# Dash App (UI)
# -----------------------
app = Dash(__name__, server=server, url_base_pathname="/", suppress_callback_exceptions=True)
app.title = 'Spark door access admin'
app._faicon = ("assets/sparkmicro_rgb.ico")

app.layout = html.Div([
    html.Div(id="header", children=[
        html.H2("Door Access Admin Portal"),
        html.Div(id="user-info"),
        html.A("Login (Azure)", href="/login", id="login-link"),
        html.A("Logout", href="/logout", id="logout-link", style={"marginRight": "10px"})
    ], style={"display": "flex", "alignItems": "center", "gap": "10px"}),

    dcc.Tabs(id="tabs", children=[
        dcc.Tab(label="Cards", value="cards"),
        # account_types tab removed per request; management of default rules is available in "Access Rules"
        dcc.Tab(label="Encres", value="encres"),
        dcc.Tab(label="Access Rules", value="rules"),
        dcc.Tab(label="Connection Logs", value="logs_connection"),
        dcc.Tab(label="Pi Devices (Admin)", value="pi")
    ], value="cards"),
    html.Div(id="tab-content")
])

# -----------------------
# Callbacks: populate header + tab content
# -----------------------
@app.callback(Output("user-info", "children"), [Input("tabs", "value")])
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
        try:
            cards = Card.query.all()
            try:
                _ = cards[0].account_type if cards else None
                df = pd.DataFrame([{"card_id": c.card_id, "owner": c.owner, "account_type": c.account_type or "visitor", 
                                    "active": c.active} for c in cards])
            except (AttributeError, Exception):
                df = pd.DataFrame([{"card_id": c.card_id, "owner": c.owner, "active": c.active} for c in cards])
        except Exception:
            df = pd.DataFrame(columns=["card_id", "owner", "active"])

        try:
            # derive account types from default access_rules (card_id = NULL)
            types = db.session.query(AccessRule.account_type).filter(AccessRule.card_id == None).distinct().all()
            account_type_options = [{"label": t[0], "value": t[0]} for t in types if t and t[0]]
            # ensure 'custom' option is present
            if not any(o['value'] == 'custom' for o in account_type_options):
                account_type_options.append({"label": "custom", "value": "custom"})
        except:
            account_type_options = [
                {"label": "engineer", "value": "engineer"},
                {"label": "manager", "value": "manager"},
                {"label": "visitor", "value": "visitor"},
                {"label": "custom", "value": "custom"}
            ]

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
                html.Label("Account Type:"),
                dcc.RadioItems(
                    id="new-card-account-type",
                    options=account_type_options,
                    value="visitor",
                    inline=True
                ),
                html.Button("Add Card", id="add-card-btn"),
                html.Button("Toggle Active Selected Card", id="toggle-card-btn", style={"marginLeft": "10px"}),
            ]),
            html.Button("Delete Selected Card", id="delete-card-btn"),
            html.Div(id="cards-msg")
        ])

    if tab == "encres":
        encres = EncreDevice.query.all()
        df = pd.DataFrame([{"encre_id": d.encre_id, "encre_name": d.encre_name, "description": d.description, 
                            "active": d.active} for d in encres])
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
            html.Button("Toggle Active Selected Encre", id="toggle-encre-btn", style={"marginLeft": "10px"}),
            html.Div(id="encres-msg")
        ])

    if tab == "rules":
        rules = AccessRule.query.all()
        encres = EncreDevice.query.all()
        encre_names = {d.encre_id: d.encre_name for d in encres}

        df = pd.DataFrame([{
            "id": r.id,
            "card_id": r.card_id,
            "account_type": r.account_type or "",
            "encre": encre_names.get(r.encre_id, r.encre_id or "All"),
            "access_from": r.access_from.isoformat() if r.access_from else "",
            "access_to": r.access_to.isoformat() if r.access_to else ""
        } for r in rules])

        # Account type rules editor (new): list account types and allow editing default rules
        # fetch distinct default account types from access_rules where card_id is NULL
        types = db.session.query(AccessRule.account_type).filter(AccessRule.card_id == None).distinct().all()
        at_rows = []
        for t in types:
            type_name = t[0]
            default_rules = []
            if type_name:
                drs = AccessRule.query.filter_by(card_id=None, account_type=type_name).all()
                for r in drs:
                    default_rules.append({"encre_id": r.encre_id, "access_from": r.access_from.isoformat() if r.access_from else "", 
                                          "access_to": r.access_to.isoformat() if r.access_to else ""})
            at_rows.append({"type_name": type_name, "default_rules": json.dumps(default_rules)})
        at_df = pd.DataFrame(at_rows)

        return html.Div([
            html.H3("Access Rules"),
            html.Div([
                html.H4("Per-card rules"),
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
                        options=[{"label": "None", "value": ""}] + [{"label": "All Encres", "value": "all"}] + 
                                [{"label": d.encre_name, "value": d.encre_id} for d in encres],
                        value=""
                    ),
                    dcc.Input(id="rule-from", placeholder="HH:MM", type="text"),
                    dcc.Input(id="rule-to", placeholder="HH:MM", type="text"),
                    html.Button("Add Rule", id="add-rule-btn")
                ]),
                html.Button("Delete Selected Rule", id="delete-rule-btn"),
                html.Div(id="rules-msg")
            ], style={"marginBottom": "30px"}),

            html.Hr(),
            html.Div([
                html.H4("Account Type Default Rules (edit here to update all non-custom cards)"),
                html.Div([
                    html.Label("Account Types:"),
                    dash_table.DataTable(
                        id="account-types-table",
                        columns=[{"name": "type_name", "id": "type_name"}],
                        data=at_df[["type_name"]].to_dict("records") if not at_df.empty else [],
                        row_selectable="single",
                        page_size=10
                    )
                ], style={"width": "32%", "display": "inline-block", "verticalAlign": "top", "marginRight": "20px"}),
                html.Div([
                    html.Label("Default Rules for selected type:"),
                    dash_table.DataTable(
                        id="atr-default-table",
                        columns=[
                            {"name": "encre_id", "id": "encre_id"},
                            {"name": "access_from", "id": "access_from"},
                            {"name": "access_to", "id": "access_to"}
                        ],
                        data=[],
                        row_selectable="single",
                        page_size=10
                    ),
                    html.Div([
                        html.Label("Selected Type:"),
                        dcc.Input(id="atr-type-name", placeholder="type_name", type="text", readOnly=True),
                        html.Br(),
                        html.Label("Select Encre/Door:"),
                        dcc.RadioItems(
                            id="atr-encre-select",
                            options=[{"label": "None", "value": ""}] + [{"label": "All Encres", "value": "all"}] + 
                                    [{"label": d.encre_name, "value": d.encre_id} for d in encres],
                            value=""
                        ),
                        dcc.Input(id="atr-from", placeholder="HH:MM:SS", type="text"),
                        dcc.Input(id="atr-to", placeholder="HH:MM:SS", type="text"),
                        html.Button("Add Default Rule", id="atr-add-rule-btn", style={"marginTop": "8px"}),
                        html.Button("Delete Selected Default Rule", id="atr-delete-rule-btn", style={"marginLeft": "8px"}),
                        html.Br(),
                        html.Button("Save Account Type Rules", id="s" \
                        "ave-atr-btn", style={"marginTop": "8px"}),
                        html.Div(id="atr-msg")
                    ], style={"marginTop": "8px"})
                ], style={"width": "60%", "display": "inline-block", "verticalAlign": "top"})
            ])
        ])

    if tab == "logs_connection":
        logs = ConnectionLog.query.order_by(ConnectionLog.last_connection.desc()).all()
        data = [{"numTag": l.numTag, "tagEncre": l.tagEncre, "last_connection": l.last_connection.isoformat(),
                  "result": l.result if l.last_connection else ""} for l in logs]
        df = pd.DataFrame(data, columns=["numTag", "tagEncre", "last_connection", "result"])
        return html.Div([
             html.H3("Connection Logs"),
             dash_table.DataTable(id="connection-table", columns=[{"name": c, "id": c} for c in df.columns], 
                                  data=df.to_dict("records"), page_size=20),
             html.Button("Refresh", id="refresh-connection-logs")
        ])

    if tab == "pi":
        devices = PiDevice.query.all()
        df = pd.DataFrame([{"device_id": d.device_id, "description": d.description, "enabled": d.enabled} for d in devices])
        return html.Div([
            html.H3("Raspberry Pi Devices"),
            dash_table.DataTable(id="pi-table", columns=[{"name": c, "id": c} for c in df.columns], 
                                 data=df.to_dict("records"), row_selectable="single"),
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
# Callbacks: Cards (Add/Delete/Toggle)
# -----------------------
@app.callback(
    Output("cards-msg", "children"),
    [Input("add-card-btn", "n_clicks"), Input("delete-card-btn", "n_clicks"), Input("toggle-card-btn", "n_clicks")],
    [State("new-card-id", "value"), State("new-card-owner", "value"), State("new-card-account-type", "value"), 
     State("cards-table", "selected_rows"), State("cards-table", "data")]
)
def handle_cards(add_click, delete_click, toggle_click, new_card_id, new_card_owner, account_type, selected_rows, table_data):
    triggered = ctx.triggered_id

    if triggered == "add-card-btn":
        if not new_card_id:
            return "card_id required"

        # Ensure account type is selected and not empty
        if not account_type:
            return "account_type required"

        # if not custom, make sure the account type exists and has default rules saved
        if account_type != "custom":
            types_resp = server.test_client().get("/api/admin/account_type_rules")
            try:
                types_json = types_resp.get_json()
                matching = [t for t in types_json if t.get("type_name") == account_type]
                if not matching:
                    return "Selected account type is not defined (save a default in Account Type section first)"
                # if we want to require non-empty default rules
                if not matching[0].get("default_rules"):
                    return "Selected account type has no default rules defined; please add at least one default rule"
            except Exception:
                return "Error fetching account type list"

        try:
            res = server.test_client().post(
                "/api/admin/cards",
                json={"card_id": new_card_id, "owner": new_card_owner or "", "account_type": account_type or "visitor"},
                content_type='application/json'
            )
            if res.status_code == 200:
                return "Card added successfully (rules set based on account type if not custom)"
            else:
                try:
                    error_data = res.get_json()
                    return f"Error: {error_data.get('error', 'Unknown error')}"
                except:
                    return f"Error: Status {res.status_code}"
        except Exception as e:
            return f"Exception: {str(e)}"

    if triggered == "delete-card-btn":
        if not selected_rows:
            return "Select a row first"
        row = table_data[selected_rows[0]]
        card_id = row["card_id"]

        try:
            res = server.test_client().delete("/api/admin/cards", json={"card_id": card_id}, content_type='application/json')
            if res.status_code == 200:
                return "Card deleted"
            else:
                try:
                    error_data = res.get_json()
                    return f"Error: {error_data.get('error', 'Unknown error')}"
                except:
                    return f"Error: Status {res.status_code}"
        except Exception as e:
            return f"Exception: {str(e)}"

    if triggered == "toggle-card-btn":
        if not selected_rows:
            return "Select a row first"
        row = table_data[selected_rows[0]]
        card_id = row["card_id"]
        try:
            res = server.test_client().post("/api/admin/cards/toggle", json={"card_id": card_id})
            if res.status_code == 200:
                payload = res.get_json()
                return f"Card {card_id} active={payload.get('active')}"
            else:
                return f"Error toggling card: {res.get_data(as_text=True)}"
        except Exception as e:
            return f"Exception: {str(e)}"

    return ""

# -----------------------
# Callbacks: Encres (Add/Delete/Toggle)
# -----------------------
@app.callback(
    Output("encres-msg", "children"),
    [Input("add-encre-btn", "n_clicks"), Input("delete-encre-btn", "n_clicks"), Input("toggle-encre-btn", "n_clicks")],
    [State("new-encre-id", "value"), State("new-encre-name", "value"), State("new-encre-desc", "value"), 
     State("encres-table", "selected_rows"), State("encres-table", "data")]
)
def handle_encres(add_click, delete_click, toggle_click, new_id, new_name, new_desc, selected_rows, table_data):
    triggered = ctx.triggered_id
    if triggered == "add-encre-btn":
        if not new_id or not new_name:
            return "encre_id and encre_name required"
        res = server.test_client().post("/api/admin/encres", json={"encre_id": new_id, "encre_name": new_name, "description": new_desc or ""})
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

    if triggered == "toggle-encre-btn":
        if not selected_rows:
            return "Select a row first"
        row = table_data[selected_rows[0]]
        encre_id = row["encre_id"]
        encre = EncreDevice.query.filter_by(encre_id=encre_id).first()
        if not encre:
            return "Encre not found"
        encre.active = not encre.active
        db.session.commit()
        return f"Encre {encre_id} active={encre.active}"

    return ""

# -----------------------
# Callbacks: Rules (per-card) and Account Type Rules (in Access Rules tab)
# -----------------------
@app.callback(
    Output("rules-msg", "children"),
    [Input("add-rule-btn", "n_clicks"), Input("delete-rule-btn", "n_clicks")],
    [State("rule-card-id", "value"), State("rule-encre-select", "value"), State("rule-from", "value"), 
     State("rule-to", "value"), State("rules-table", "selected_rows"), State("rules-table", "data")]
)
def handle_rules(add_click, delete_click, card_id, encre_id, rfrom, rto, selected_rows, table_data):
    triggered = ctx.triggered_id
    if triggered == "add-rule-btn":
        if not card_id:
            return "card_id required"
        # If encre_id == "all", use None => indicates all encres / no specific door restriction
        encre_val = None if encre_id in ("", "all") else encre_id
        res = server.test_client().post("/api/admin/access_rule", json={
            "card_id": card_id,
            "encre_id": encre_val,
            "access_from": rfrom,
            "access_to": rto
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
    [Output("atr-type-name", "value"), 
     Output("atr-default-table", "data"), 
     Output("atr-msg", "children")],
    [Input("account-types-table", "selected_rows"),
     Input("atr-add-rule-btn", "n_clicks"), 
     Input("atr-delete-rule-btn", "n_clicks"),
     Input("save-atr-btn", "n_clicks")],
    [State("account-types-table", "data"),
     State("atr-type-name", "value"), 
     State("atr-encre-select", "value"), 
     State("atr-from", "value"), 
     State("atr-to", "value"), 
     State("atr-default-table", "selected_rows"), 
     State("atr-default-table", "data")]
)
def handle_account_type_rules(selected_type_rows, add_click, delete_click, save_click,
                               types_data, type_name, encre_val, af, at, sel_rows, table_data):
    triggered = ctx.triggered_id
    
    # When selecting an account type from the list
    if triggered == "account-types-table":
        if not selected_type_rows:
            return "", [], ""
        row = types_data[selected_type_rows[0]]
        type_name = row.get("type_name")
        # load default rules from DB
        rules = AccessRule.query.filter_by(card_id=None, account_type=type_name).all()
        data = [{"encre_id": r.encre_id or "", 
                 "access_from": r.access_from.isoformat() if r.access_from else "",
                 "access_to": r.access_to.isoformat() if r.access_to else ""} for r in rules]
        return type_name, data, ""
    
    # Add a default rule
    if triggered == "atr-add-rule-btn":
        if not type_name:
            return type_name or "", table_data or [], "Select an account type first"
        # append to local table data
        encre = None if encre_val in ("", "all") else encre_val
        new_row = {"encre_id": encre or "", "access_from": af or "", "access_to": at or ""}
        table_data = table_data or []
        table_data.append(new_row)
        return type_name, table_data, "Added default rule (unsaved)"
    
    # Delete a default rule
    if triggered == "atr-delete-rule-btn":
        if not sel_rows:
            return type_name or "", table_data or [], "Select a default rule row to delete"
        idx = sel_rows[0]
        if table_data and 0 <= idx < len(table_data):
            del table_data[idx]
            return type_name, table_data, "Removed default rule (unsaved)"
        return type_name or "", table_data or [], "Index out of range"
    
    # Save account type rules
    if triggered == "save-atr-btn":
        if not type_name:
            return type_name or "", table_data or [], "Select an account type first"
        # validate rules_table_data list
        rules_table_data = table_data or []
        # convert from table_data to API format
        payload_rules = []
        for r in rules_table_data:
            encre_id = r.get("encre_id") or None
            af_val = r.get("access_from") or ""
            at_val = r.get("access_to") or ""
            # check times
            try:
                if af_val:
                    datetime.datetime.strptime(af_val, "%H:%M:%S")
                if at_val:
                    datetime.datetime.strptime(at_val, "%H:%M:%S")
            except Exception as e:
                return type_name, table_data, f"Invalid time format in row: {e}"
            payload_rules.append({"encre_id": encre_id, "access_from": af_val, "access_to": at_val})
        # PUT to backend
        res = server.test_client().put("/api/admin/account_type_rules", 
                                       json={"type_name": type_name, "default_rules": payload_rules})
        if res.status_code == 200:
            return type_name, table_data, "Account type default rules saved and propagated"
        try:
            return type_name, table_data, f"Error: {res.get_json()}"
        except:
            return type_name, table_data, f"Error status: {res.status_code}"
    
    # Default/initial state (no trigger or initial load)
    return type_name or "", table_data or [], ""

# -----------------------
# Callbacks: Pi devices
# -----------------------
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

# -----------------------
# Initialize DB helper route (for dev only)
# -----------------------
@server.route("/dev/init_db")
def dev_init_db():
    if server.debug or os.environ.get("DEV_INIT") == "1":
        db.create_all()
        # create default account-type rules as AccessRule rows with card_id=None and account_type=<type_name>
        default_types = {
            "engineer": [{"encre_id": None, "access_from": "06:00", "access_to": "21:00"}],
            "manager": [{"encre_id": None, "access_from": "07:00", "access_to": "18:00"}],
            "visitor": [{"encre_id": None, "access_from": "08:00", "access_to": "18:00"}],
            "custom": []  # custom has no defaults
        }
        for type_name, rules in default_types.items():
            # if no default rules recorded yet, insert them
            existing = AccessRule.query.filter_by(card_id=None, account_type=type_name).first()
            if not existing and rules:
                for rr in rules:
                    af_time = datetime.datetime.strptime(rr.get("access_from"), "%H:%M").time() if rr.get("access_from") else None
                    at_time = datetime.datetime.strptime(rr.get("access_to"), "%H:%M").time() if rr.get("access_to") else None
                    ar = AccessRule(card_id=None, account_type=type_name, encre_id=rr.get("encre_id"), 
                                    access_from=af_time, access_to=at_time)
                    db.session.add(ar)
        db.session.commit()
        return "db initialized with default account types"
    return "disabled", 403
# -----------------------
# Run
# -----------------------
if __name__ == "__main__":
    print("Starting Dash app. FRONTEND_BASE:", FRONTEND_BASE)
    server.run(host="0.0.0.0", port=8000, debug=True)
else:
    print("Dash app loaded as module.")
    with server.app_context():
        db.create_all()
