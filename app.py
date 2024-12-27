import os
import requests
import certifi
import time
from flask import Flask, request
import webbrowser
 
app = Flask(__name__)
 
# Configuration
CLIENT_ID = "0cc547df-de5a-4ff2-90da-e5a76ab54491"
TENANT_ID = "c9c17f04-6109-4571-8b35-f9c3635f74b3"
CLIENT_SECRET = os.getenv("CLIENT_SECRET")  # Load CLIENT_SECRET from environment variables
SCOPE = "api://0cc547df-de5a-4ff2-90da-e5a76ab54491/.default"  # Corrected scope
REDIRECT_URI = "https://flaskwebapptoken.azurewebsites.net/callback"  # Updated for Azure deployment
AUTH_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
 
# Global variables
access_token = None
token_expiry_time = None
 
@app.route('/')
def index():
    """Initiates the authorization process."""
    auth_url = (
        f"{AUTH_URL}?client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}&scope={SCOPE}"
    )
    webbrowser.open(auth_url)  # Open the authorization URL in the browser
    return 'Please check your browser for authorization.'
 
@app.route('/callback')
def callback():
    """Handles the redirect from Azure and exchanges the authorization code for a token."""
    auth_code = request.args.get('code')
    if auth_code:
        # Exchange the authorization code for the token
        token = exchange_code_for_token(auth_code)
        return f"Bearer Token: {token}"
    else:
        return "Error: No code found in the callback."
 
def exchange_code_for_token(auth_code):
    """Exchanges the authorization code for an access token."""
    global access_token, token_expiry_time
 
    payload = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,  # Add the client secret here for client credentials flow
        'grant_type': 'authorization_code',
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPE,
        'code': auth_code
    }
 
    # Send POST request to the token endpoint
    response = requests.post(TOKEN_URL, data=payload, verify=certifi.where())
    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data['access_token']
        expires_in = token_data['expires_in']  # Token expiry time in seconds
        token_expiry_time = time.time() + expires_in
        print(f"Token fetched successfully! Expires in {expires_in} seconds.")
        return access_token
    else:
        raise Exception(f"Failed to fetch token: {response.status_code} {response.text}")
 
def get_access_token_with_client_credentials():
    """Fetches a token using client credentials flow (without the authorization code)."""
    global access_token, token_expiry_time
 
    payload = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,  # Add the client secret here for client credentials flow
        'grant_type': 'client_credentials',
        'scope': SCOPE  # Using the corrected scope with .default
    }
 
    # Send POST request to the token endpoint
    response = requests.post(TOKEN_URL, data=payload, verify=certifi.where())
    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data['access_token']
        expires_in = token_data['expires_in']  # Token expiry time in seconds
        token_expiry_time = time.time() + expires_in
        print(f"Token fetched successfully! Expires in {expires_in} seconds.")
        return access_token
    else:
        raise Exception(f"Failed to fetch token: {response.status_code} {response.text}")
 
@app.route("/check-secrets")
def check_secrets():
    """Endpoint to check the secrets (Client ID and Client Secret)."""
    return f"Client ID: {CLIENT_ID}, Client Secret: {CLIENT_SECRET}"
 
if __name__ == "__main__":
    # Fetch the token directly with client credentials if no authorization code is involved
    access_token = get_access_token_with_client_credentials()
    print(f"Access token: {access_token}")
 
    # This is for Gunicorn when running in production (Azure will use this to run the app)
    app.run(host='0.0.0.0', port=8000)