from flask import (
    Flask, 
    render_template, 
    request, 
    redirect, 
    url_for, 
    flash, 
    session,
    jsonify
)
from werkzeug.utils import secure_filename
import os
import csv
import json
import requests
from functools import wraps
from datetime import datetime
import logging
from oauthlib.oauth2 import WebApplicationClient
from requests.auth import HTTPBasicAuth
import argparse
from urllib.parse import urlencode, parse_qs
import secrets
import uuid
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('--test', action='store_true', help='Run in test mode')
args = parser.parse_args()

app = Flask(__name__, template_folder='templates')

# Load appropriate config
if args.test:
    logger.info("Running in TEST mode")
    from config import TestConfig as CurrentConfig
else:
    logger.info("Running in PRODUCTION mode")
    from config import ProductionConfig as CurrentConfig

# Apply configuration
app.config.from_object(CurrentConfig)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'csv'}

# OAuth2 client setup
client = WebApplicationClient(app.config['OAUTH2_CLIENT_ID'])

# Configure for test mode if needed
if args.test:
    # Allow OAuth2 without SSL in test mode
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    # Disable SSL verification warnings for test mode
    os.environ['PYTHONWARNINGS'] = 'ignore:Unverified HTTPS request'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'oauth_token' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_redirect_uri():
    """Get the redirect URI with the correct protocol"""
    if app.config['USE_HTTPS']:
        return url_for('oauth2_callback', _external=True, _scheme='https')
    return url_for('oauth2_callback', _external=True, _scheme='http')

@app.route('/')
def index():
    if 'oauth_token' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', test_mode=args.test)


@app.route('/login')
def login():
    # Clear any existing session data
    session.clear()
    
    # Generate the authorization URL
    authorization_url = client.prepare_request_uri(
        app.config['OAUTH2_AUTH_URL'],
        redirect_uri=get_redirect_uri(),
        scope=['read', 'write'],
        state=os.urandom(16).hex()  # Add state parameter for security
    )
    return redirect(authorization_url)

@app.route('/oauth2_callback')
def oauth2_callback():
    # Get authorization response from request
    code = request.args.get('code')
    if not code:
        flash('Failed to get authorization code')
        return redirect(url_for('index'))

    try:
        token_url, headers, body = client.prepare_token_request(
            app.config['OAUTH2_TOKEN_URL'],
            authorization_response=request.url,
            redirect_url=get_redirect_uri(),
            code=code,
            client_id=app.config['OAUTH2_CLIENT_ID'],  # Add client_id to body
            client_secret=app.config['OAUTH2_CLIENT_SECRET']  # Add client_secret to body
        )
        
        # Debug logging
        logger.info(f"Token request URL: {token_url}")
        logger.info(f"Token request headers: {headers}")
        logger.info(f"Token request body: {body}")
        
        # Make the token request without auth in headers (since we're including in body)
        token_response = requests.post(
            token_url, 
            headers=headers, 
            data=body,
            verify=not args.test
        )

        # Log the response for debugging
        logger.info(f"Token response status: {token_response.status_code}")
        logger.info(f"Token response: {token_response.text}")

        if token_response.status_code != 200:
            logger.error(f"Token response error: {token_response.text}")
            flash('Failed to obtain access token')
            return redirect(url_for('index'))

        # Parse and store the tokens
        token_data = token_response.json()
        session['oauth_token'] = token_data
        
        flash('Successfully authenticated')
        return redirect(url_for('index'))

    except Exception as e:
        logger.error(f"OAuth callback error: {str(e)}")
        flash(f'Authentication error: {str(e)}')
        return redirect(url_for('index'))
def update_user(user_id, user_data, access_token):
    """Update a user in Brivo via API"""
    headers = {
        'Authorization': f"Bearer {access_token}",
        'Content-Type': 'application/json'
    }
    
    # Convert date formats
    if 'effectiveFrom' in user_data:
        try:
            dt = datetime.strptime(user_data['effectiveFrom'], '%Y-%m-%d')
            user_data['effectiveFrom'] = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            logger.warning(f"Invalid effectiveFrom date format for user {user_id}")
            
    if 'effectiveTo' in user_data:
        try:
            dt = datetime.strptime(user_data['effectiveTo'], '%Y-%m-%d')
            user_data['effectiveTo'] = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            logger.warning(f"Invalid effectiveTo date format for user {user_id}")

    url = f"{app.config['API_BASE_URL']}/users/{user_id}"
    try:
        response = requests.put(
            url, 
            headers=headers, 
            json=user_data,
            verify=not args.test  # Skip SSL verification in test mode only
        )
        response.raise_for_status()
        return True, None
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to update user {user_id}: {str(e)}"
        if hasattr(e.response, 'text'):
            error_msg += f" - {e.response.text}"
        logger.error(error_msg)
        return False, error_msg

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('index'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        results = {
            'success': 0,
            'failed': 0,
            'errors': []
        }

        try:
            with open(filepath, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    user_id = row.pop('id', None)  # Remove and get the ID field
                    if not user_id:
                        results['failed'] += 1
                        results['errors'].append(f"Row missing user ID: {row}")
                        continue

                    # Clean empty values from the row
                    user_data = {k: v.strip() for k, v in row.items() if v and v.strip()}
                    
                    success, error = update_user(
                        user_id, 
                        user_data, 
                        session['oauth_token']['access_token']
                    )

                    if success:
                        results['success'] += 1
                    else:
                        results['failed'] += 1
                        results['errors'].append(error)

        except Exception as e:
            flash(f'Error processing CSV: {str(e)}')
            logger.error(f"CSV processing error: {str(e)}")
            return redirect(url_for('index'))
        finally:
            # Clean up the uploaded file
            os.remove(filepath)

        flash(f"Updates completed. Success: {results['success']}, Failed: {results['failed']}")
        if results['errors']:
            flash(f"Errors: {'; '.join(results['errors'][:5])}")
            if len(results['errors']) > 5:
                flash(f"...and {len(results['errors']) - 5} more errors")

        return redirect(url_for('index'))

    flash('Invalid file type')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)