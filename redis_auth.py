#  Authorization code with other functionlaity too 
from flask import Flask, redirect, url_for, session, request, jsonify #data - dictinary into json format for http responses 
from flask_session import Session
from authlib.integrations.flask_client import OAuth
from functools import wraps  #  for decorator function - a function that helps to preserve the original function metadata
import os  # interacting with os, env variable 
import redis  # python library to integrate with redis database 
import json  # python object into json and vice-versa 
import binascii  # nonce, sessin security , to convert binary data 
from datetime import datetime
from flask import render_template

app = Flask(__name__)

# Redis configuration
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'auth0_session:'
app.config['SESSION_REDIS'] = redis.StrictRedis(
    host='localhost',
    port=6380,
    db=0,
    ssl=True,
    ssl_certfile=os.getenv('REDIS_CERT_FILE'),
    ssl_keyfile=os.getenv('REDIS_KEY_FILE'),
    ssl_ca_certs=os.getenv('REDIS_CA_FILE')
)

Session(app)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

# Set up OAuth client for Auth0
oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=os.environ.get('AUTH0_CLIENT_ID'),    
    client_secret=os.environ.get('AUTH0_CLIENT_SECRET'),
    authorize_url=f'https://{os.environ.get("AUTH0_DOMAIN")}/authorize',
    access_token_url=f'https://{os.environ.get("AUTH0_DOMAIN")}/oauth/token',
    api_base_url=f'https://{os.environ.get("AUTH0_DOMAIN")}/userinfo',
    client_kwargs={'scope': 'openid profile email'},
    jwks_uri='https://dev-3otkbyaimmymvxpt.us.auth0.com/.well-known/jwks.json'
)

def generate_nonce():
    return binascii.hexlify(os.urandom(16)).decode()

def decode_redis_value(value):
    """Safely decode Redis binary values"""
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode('utf-8')
    return value

def get_user_session(redis_client, user_id):
    """Get existing session ID for a user if it exists"""
    return decode_redis_value(redis_client.get(f"user:{user_id}:session_id"))

def list_active_sessions(redis_client):
    """List all active sessions in Redis"""
    keys = redis_client.keys("user:*:session_id")
    sessions = {}
    for key in keys:
        user_id = key.decode('utf-8').split(':')[1]
        session_id = decode_redis_value(redis_client.get(key))
        sessions[user_id] = session_id
    return sessions

def store_user_session(redis_client, user_id, session_id, token):
    """Store user session data in Redis"""
    # Set session expiry to 24 hours (86400 seconds)
    expiry = 86400
    
    # Store session ID with expiry
    redis_client.setex(f"user:{user_id}:session_id", expiry, session_id)
    
    # Store tokens with the same expiry
    if 'access_token' in token:
        redis_client.setex(f"auth0_session:{session_id}:access_token", expiry, token['access_token'])
    if 'id_token' in token:
        redis_client.setex(f"auth0_session:{session_id}:id_token", expiry, token['id_token'])
    if 'refresh_token' in token:
        redis_client.setex(f"auth0_session:{session_id}:refresh_token", expiry, token['refresh_token'])

def clear_user_data(redis_client, user_id):
    """Clear all user data from Redis"""
    session_id = get_user_session(redis_client, user_id)
    if session_id:
        redis_client.delete(
            f"user:{user_id}:session_id",
            f"user:{user_id}:permissions",
            f"auth0_session:{session_id}:access_token",
            f"auth0_session:{session_id}:id_token",
            f"auth0_session:{session_id}:refresh_token"
        )

def requires_auth(permissions=None):
    """Authorization decorator"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user' not in session:
                return redirect(url_for('login')) 

            redis_client = app.config['SESSION_REDIS']
            user_id = session['user']['sub']
            
            # Verify session
            stored_session_id = get_user_session(redis_client, user_id)
            if not stored_session_id:
                session.clear()
                return redirect(url_for('login'))
            
            # Update session ID in current session to match stored one
            session['session_id'] = stored_session_id
            
            # Check permissions if specified
            if permissions:
                user_permissions = redis_client.smembers(f"user:{user_id}:permissions")
                user_permissions = {p.decode('utf-8') for p in user_permissions}
                required_permissions = permissions if isinstance(permissions, list) else [permissions]
                
                if not all(p in user_permissions for p in required_permissions):
                    return redirect(url_for('no_permission'))
            
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route('/')
def home():
    redis_client = app.config['SESSION_REDIS']
    active_sessions = list_active_sessions(redis_client)
    
    if 'user' in session:
        return jsonify({
            'message': "Welcome back! You are logged in.",
            'active_sessions': active_sessions
        })
    return render_template('home.html')

@app.route('/login')
def login():
    nonce = generate_nonce()
    session['nonce'] = nonce
    return auth0.authorize_redirect(
        redirect_uri=url_for('auth0_callback', _external=True),
        nonce=nonce
    )

@app.route('/callback')
def auth0_callback():
    token = auth0.authorize_access_token()
    nonce = session.pop('nonce', None)
    
    if not nonce:
        return 'Missing nonce', 400
    
    user = auth0.parse_id_token(token, nonce=nonce)
    user_id = user['sub']
    redis_client = app.config['SESSION_REDIS']
    
    # Always check for existing session
    existing_session_id = get_user_session(redis_client, user_id)
    
    if existing_session_id:
        # Use existing session ID to maintain the same session across browsers
        session_id = existing_session_id
    else:
        # Generate new session ID only for new users
        session_id = binascii.hexlify(os.urandom(16)).decode()
    
    # Store session data
    store_user_session(redis_client, user_id, session_id, token)
    
    # Update session
    session['user'] = user
    session['session_id'] = session_id
    
    # Set up permissions
    permissions = ['read:dashboard']  # Basic permission
    permission_key = f"user:{user_id}:permissions"
    
    # Only set permissions if they don't exist
    if not redis_client.exists(permission_key):
        redis_client.sadd(permission_key, *permissions)
    
    return redirect('/dashboard')

@app.route('/dashboard')
@requires_auth('read:dashboard')
def dashboard():
    redis_client = app.config['SESSION_REDIS']
    user_id = session['user']['sub']
    
    # Get user permissions
    user_permissions = redis_client.smembers(f"user:{user_id}:permissions")
    user_permissions = [p.decode('utf-8') for p in user_permissions]
    
    # Get all active sessions
    active_sessions = list_active_sessions(redis_client)
    
    # Get current session info
    current_session = {
        'session_id': session.get('session_id'),
        'tokens': {
            'access_token': decode_redis_value(
                redis_client.get(f"auth0_session:{session.get('session_id')}:access_token")
            ),
            'id_token': decode_redis_value(
                redis_client.get(f"auth0_session:{session.get('session_id')}:id_token")
            )
        }
    }
    
    current_user = {
        'id': user_id,
        'email': session['user'].get('email'),
        'name': session['user'].get('name'),
        'permissions': user_permissions
    }

    return render_template(
        'dashboard.html',
        current_user=current_user,
        current_session=current_session,
        active_sessions=active_sessions
    )

@app.route('/no_permission')
def no_permission():
    return jsonify({
        'error': 'Forbidden',
        'message': 'You don\'t have permission to access this resource'
    }), 403

@app.route('/logout')
def logout():
    if 'user' in session:
        user_id = session['user']['sub']
        redis_client = app.config['SESSION_REDIS']
        clear_user_data(redis_client, user_id)
    
    session.clear()
    
    return redirect(
        f'https://{os.environ.get("AUTH0_DOMAIN")}/v2/logout'
        f'?client_id={os.environ.get("AUTH0_CLIENT_ID")}'
        f'&returnTo=http://localhost:5000'
    )

if __name__ == '__main__':
    app.run(debug=True)
