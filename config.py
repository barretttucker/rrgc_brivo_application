# config.py
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
class ProductionConfig(Config):
    OAUTH2_CLIENT_ID = os.environ.get('BRIVO_CLIENT_ID')
    OAUTH2_CLIENT_SECRET = os.environ.get('BRIVO_CLIENT_SECRET')
    OAUTH2_AUTH_URL = "https://auth.brivo.com/oauth/authorize"
    OAUTH2_TOKEN_URL = "https://auth.brivo.com/oauth/token"
    API_BASE_URL = "https://api.brivo.com/v1/api"
    USE_HTTPS = True
    
class TestConfig(Config):
    OAUTH2_CLIENT_ID = "test-client-id"
    OAUTH2_CLIENT_SECRET = "test-client-secret"
    OAUTH2_AUTH_URL = "https://localhost:5001/oauth/authorize"
    OAUTH2_TOKEN_URL = "https://localhost:5001/oauth/token"
    API_BASE_URL = "https://localhost:5001/v1/api"
    OAUTHLIB_INSECURE_TRANSPORT = "1"  # Allow OAuth2 over HTTP in test mode
    USE_HTTPS = False  # Use HTTP for the main app in test mode