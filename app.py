import os
import requests
import certifi
import time
from flask import Flask, jsonify

app = Flask(__name__)

# Configuration
CLIENT_ID = "0cc547df-de5a-4ff2-90da-e5a76ab54491"
TENANT_ID = "c9c17f04-6109-4571-8b35-f9c3635f74b3"
CLIENT_SECRET = os.getenv("CLIENT_SECRET")  # Load CLIENT_SECRET from environment variables
SCOPE = "api://0cc547df-de5a-4ff2-90da-e5a76ab54491/.default"  # Corrected scope
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

# Global variables
access_token = None
token_expiry_time = None


def get_access_token_with_client_credentials():
    """Fetches a token using client credentials flow."""
    global access_token, token_expiry_time

    payload = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'client_credentials',
        'scope': SCOPE
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


@app.route('/')
def get_token():
    """Returns the current access token or fetches a new one if expired."""
    global access_token, token_expiry_time

    # Check if the token is expired or missing
    if not access_token or time.time() >= token_expiry_time:
        try:
            access_token = get_access_token_with_client_credentials()
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"access_token": access_token})


@app.route("/check-secrets")
def check_secrets():
    """Endpoint to check the secrets (Client ID and Client Secret)."""
    client_secret_status = "Set" if CLIENT_SECRET else "Not Set"
    return f"Client ID: {CLIENT_ID}, Client Secret: {client_secret_status}"


if __name__ == "__main__":
    # Fetch the initial token on startup
    try:
        access_token = get_access_token_with_client_credentials()
        print(f"Access token: {access_token}")
    except Exception as e:
        print(f"Failed to fetch token on startup: {e}")

    # Run the app
    app.run(host='0.0.0.0', port=8000)
