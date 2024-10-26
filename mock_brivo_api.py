# mock_brivo_api.py
from flask import Flask, request, jsonify, redirect
import uuid
import jwt
import datetime
from werkzeug.security import check_password_hash, generate_password_hash
import logging
from urllib.parse import urlencode, parse_qs
import json
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# In-memory database
class MockDB:
    def __init__(self):
        self.users = {}  # User data store
        self.tokens = {} # Token store
        self.clients = {
            "test-client-id": {
                "client_secret": "test-client-secret",
                "redirect_uris": [
                    "http://localhost:5000/oauth2_callback",
                    "https://localhost:5000/oauth2_callback"
                ]
            }
        }
        
        # Add some test users
        self.users = {
            "442211": {
                "id": "442211",
                "firstName": "John",
                "lastName": "Smith",
                "middleName": "Robert",
                "externalId": "EMP123",
                "pin": "1234",
                "effectiveFrom": "2024-01-01T00:00:00Z",
                "effectiveTo": "2024-12-31T23:59:59Z",
                "bleTwoFactorExempt": True,
                "suspended": False,
                "created": "2024-01-01T00:00:00Z",
                "updated": "2024-01-01T00:00:00Z"
            },
            "442212": {
                "id": "442212",
                "firstName": "Jane",
                "lastName": "Doe",
                "externalId": "EMP124",
                "pin": "5678",
                "effectiveFrom": "2024-02-01T00:00:00Z",
                "effectiveTo": "2024-12-31T23:59:59Z",
                "bleTwoFactorExempt": False,
                "suspended": False,
                "created": "2024-01-01T00:00:00Z",
                "updated": "2024-01-01T00:00:00Z"
            }
        }

db = MockDB()

# JWT configuration
JWT_SECRET = "mock-jwt-secret-key"
JWT_ALGORITHM = "HS256"

def create_access_token(client_id, scope):
    """Create a mock JWT access token"""
    now = datetime.datetime.utcnow()
    payload = {
        "client_id": client_id,
        "scope": scope,
        "exp": now + datetime.timedelta(hours=1),
        "iat": now,
        "jti": str(uuid.uuid4())
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def verify_auth_header():
    """Verify the Authorization header"""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# In mock_brivo_api.py, update the OAuth routes

# In mock_brivo_api.py, update the OAuth routes

@app.route('/oauth/authorize', methods=['GET'])
def authorize():
    """Mock OAuth2 authorization endpoint"""
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    
    if client_id not in db.clients:
        return jsonify({"error": "invalid_client"}), 400
        
    # Allow both HTTP and HTTPS redirects in test mode
    test_redirect_uri = redirect_uri.replace('http://', 'https://')
    if redirect_uri not in db.clients[client_id]['redirect_uris'] and \
       test_redirect_uri not in db.clients[client_id]['redirect_uris']:
        return jsonify({"error": "invalid_redirect_uri"}), 400
    
    # Generate authorization code
    auth_code = str(uuid.uuid4())
    db.tokens[auth_code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "expires_at": datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    }
    
    # Build redirect URL with authorization code
    params = {
        'code': auth_code,
        'state': request.args.get('state', '')
    }
    redirect_url = f"{redirect_uri}?{urlencode(params)}"
    return redirect(redirect_url)

@app.route('/oauth/token', methods=['POST'])
def token():
    """Mock OAuth2 token endpoint"""
    # Log the incoming request for debugging
    logger.info(f"Token request headers: {request.headers}")
    logger.info(f"Token request body: {request.form}")
    
    # Extract Basic Auth credentials
    auth = request.headers.get('Authorization', '')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    
    # If using Basic Auth, decode it
    if auth.startswith('Basic '):
        import base64
        try:
            decoded = base64.b64decode(auth[6:]).decode('utf-8')
            basic_client_id, basic_client_secret = decoded.split(':')
            client_id = basic_client_id
            client_secret = basic_client_secret
        except Exception as e:
            logger.error(f"Error decoding Basic Auth: {e}")
            return jsonify({"error": "invalid_client"}), 401

    # Verify client credentials
    if client_id not in db.clients:
        logger.error(f"Unknown client_id: {client_id}")
        return jsonify({"error": "invalid_client"}), 401
        
    if db.clients[client_id]['client_secret'] != client_secret:
        logger.error("Invalid client secret")
        return jsonify({"error": "invalid_client"}), 401

    grant_type = request.form.get('grant_type')
    
    if grant_type == 'authorization_code':
        code = request.form.get('code')
        
        # Verify authorization code
        if code not in db.tokens:
            return jsonify({"error": "invalid_grant"}), 400
            
        token_data = db.tokens[code]
        if token_data['expires_at'] < datetime.datetime.utcnow():
            return jsonify({"error": "expired_code"}), 400
            
        # Generate access token
        access_token = create_access_token(client_id, ["read", "write"])
        refresh_token = str(uuid.uuid4())
        
        # Clean up used authorization code
        del db.tokens[code]
        
        return jsonify({
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token,
            "scope": "read write"
        })

@app.route('/v1/api/users/<user_id>', methods=['GET', 'PUT'])
def user(user_id):
    """Mock User API endpoint"""
    # Verify token
    if not verify_auth_header():
        return jsonify({"error": "invalid_token"}), 401
    
    if request.method == 'GET':
        user = db.users.get(user_id)
        if not user:
            return jsonify({"code": 404, "message": "User not found"}), 404
        return jsonify(user)
        
    elif request.method == 'PUT':
        if user_id not in db.users:
            return jsonify({"code": 404, "message": "User not found"}), 404
            
        data = request.json
        user = db.users[user_id]
        
        # Update only provided fields
        for key in ['firstName', 'lastName', 'middleName', 'externalId', 'pin', 
                   'effectiveFrom', 'effectiveTo', 'bleTwoFactorExempt']:
            if key in data:
                user[key] = data[key]
                
        user['updated'] = datetime.datetime.utcnow().isoformat() + 'Z'
        
        return jsonify(user)

@app.route('/v1/api/users', methods=['POST'])
def create_user():
    """Mock Create User API endpoint"""
    # Verify token
    if not verify_auth_header():
        return jsonify({"error": "invalid_token"}), 401
    
    data = request.json
    
    # Validate required fields
    required_fields = ['firstName', 'lastName']
    for field in required_fields:
        if field not in data:
            return jsonify({
                "code": 400,
                "message": f"Missing required field: {field}"
            }), 400
    
    # Generate new user ID
    user_id = str(uuid.uuid4())
    
    # Create user object
    user = {
        "id": user_id,
        "firstName": data['firstName'],
        "lastName": data['lastName'],
        "middleName": data.get('middleName'),
        "externalId": data.get('externalId'),
        "pin": data.get('pin'),
        "effectiveFrom": data.get('effectiveFrom'),
        "effectiveTo": data.get('effectiveTo'),
        "bleTwoFactorExempt": data.get('bleTwoFactorExempt', False),
        "suspended": False,
        "created": datetime.datetime.utcnow().isoformat() + 'Z',
        "updated": datetime.datetime.utcnow().isoformat() + 'Z'
    }
    
    db.users[user_id] = user
    return jsonify(user), 201

if __name__ == '__main__':
    # Use Flask's built-in SSL context
    ssl_context = ('server.crt', 'server.key')
    app.run(
        host='localhost',
        port=5001,
        ssl_context=ssl_context,
        debug=True
    )