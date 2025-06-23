from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from datetime import datetime, timedelta
import jwt
import time
import logging
import requests

# === Prometheus ===
from prometheus_client import generate_latest, Counter, Histogram, CONTENT_TYPE_LATEST

REQUEST_COUNT = Counter('app_requests_total', 'Total HTTP Requests', ['method', 'endpoint'])
REQUEST_LATENCY = Histogram('app_request_latency_seconds', 'Request latency in seconds', ['endpoint'])

# === Fluentd Logging (qua HTTP) ===
FLUENTD_ENDPOINT = "http://192.168.40.138:8080"  # Địa chỉ Fluentd container

# === Flask Setup ===
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'supersecretkey'
CORS(app)
db = SQLAlchemy(app)

# === Rate Limiting ===
limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"], storage_uri="memory://")

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({"error": "Bạn đã vượt quá giới hạn 10 request/phút."}), 409

# === Logging setup ===
logging.basicConfig(level=logging.INFO)

@app.before_request
def start_timer():
    g.start_time = time.time()

@app.after_request
def record_metrics(response):
    if request.endpoint != 'metrics':
        resp_time = time.time() - g.start_time
        REQUEST_LATENCY.labels(request.path).observe(resp_time)
        REQUEST_COUNT.labels(request.method, request.path).inc()

        # === Ghi log ra stdout
        log_msg = f"{request.method} {request.path} {response.status_code}"
        app.logger.info(log_msg)

        # === Gửi log về Fluentd qua HTTP
        log_data = {
            'method': request.method,
            'path': request.path,
            'status': response.status_code
        }
        try:
            requests.post(FLUENTD_ENDPOINT, json=log_data, timeout=1)
        except Exception as e:
            app.logger.warning(f"Không gửi được log tới Fluentd: {e}")
    return response

@app.route('/metrics')
def metrics():
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

# === User Model ===
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100))
    dob = db.Column(db.String(20))
    email = db.Column(db.String(100))
    phone = db.Column(db.String(20))

# === Dummy Accounts ===
USER_CREDENTIALS = {
    "admin": {"password": "444", "role": "admin"},
    "user": {"password": "123", "role": "user"}
}

def generate_token(username, role):
    payload = {
        'sub': username,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        g.username = payload['sub']
        g.role = payload['role']
        return True
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token or not token.startswith("Bearer "):
            return jsonify({"error": "Cần token xác thực"}), 403
        if not verify_token(token.split(" ")[1]):
            return jsonify({"error": "Token không hợp lệ hoặc đã hết hạn"}), 403
        return f(*args, **kwargs)
    return decorated

def require_role(allowed_roles_by_method):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            role = getattr(g, 'role', None)
            if request.method in allowed_roles_by_method.get(role, []):
                return f(*args, **kwargs)
            return jsonify({"error": "Bạn không có quyền"}), 403
        return wrapped
    return decorator

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = USER_CREDENTIALS.get(username)
    if not user or user['password'] != password:
        return jsonify({'error': 'Sai thông tin đăng nhập'}), 401
    token = generate_token(username, user['role'])
    return jsonify({'token': token})

@app.route('/api/users', methods=['GET', 'POST'])
@auth_required
@require_role({
    "user": ["GET"],
    "admin": ["GET", "POST"]
})
@limiter.limit("10 per minute")
def users():
    if request.method == 'GET':
        users = User.query.all()
        return jsonify([{
            'id': u.id,
            'full_name': u.full_name,
            'dob': u.dob,
            'email': u.email,
            'phone': u.phone
        } for u in users])

    if request.method == 'POST':
        data = request.json
        user = User(**data)
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User created'}), 201

@app.route('/api/users/<int:id>', methods=['PUT', 'DELETE'])
@auth_required
@require_role({
    "admin": ["PUT", "DELETE"],
    "user": []
})
@limiter.limit("10 per minute")
def user_detail(id):
    user = User.query.get(id)
    if not user:
        return jsonify({'error': 'Không tìm thấy user'}), 404

    if request.method == 'PUT':
        for key in ['full_name', 'dob', 'email', 'phone']:
            setattr(user, key, request.json.get(key, getattr(user, key)))
        db.session.commit()
        return jsonify({'message': 'User updated'})

    if request.method == 'DELETE':
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)
