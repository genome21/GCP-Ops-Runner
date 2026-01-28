import os
import json
import subprocess
import sys
import logging
import re
from functools import wraps
from flask import Flask, request, render_template, jsonify, session, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from google.cloud import tasks_v2
from authlib.integrations.flask_client import OAuth
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', stream=sys.stdout)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")
# Apply ProxyFix to handle HTTPS behind Cloud Run
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# OAuth Setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://oauth2.googleapis.com/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using userinfo()
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

# Configuration
PROJECT_ID = os.environ.get("PROJECT_ID", "unknown-project")
REGION = os.environ.get("REGION", "us-central1")
QUEUE_NAME = os.environ.get("QUEUE_NAME", "ops-queue")
# SERVICE_URL will be populated at runtime or config
SERVICE_URL = os.environ.get("SERVICE_URL")
# The service account to use for the OIDC token when the task invokes the worker
SERVICE_ACCOUNT_EMAIL = os.environ.get("SERVICE_ACCOUNT_EMAIL")

logger.info(f"Server starting with Config: PROJECT_ID={PROJECT_ID}, REGION={REGION}, QUEUE_NAME={QUEUE_NAME}, SERVICE_ACCOUNT_EMAIL={SERVICE_ACCOUNT_EMAIL}")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def verify_oidc_token():
    """Verifies the Bearer token in the Authorization header."""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        logger.warning("Missing Authorization header in /execute request")
        return False

    try:
        token = auth_header.split(" ")[1]

        # The audience must match the target URL (e.g., https://service-url/execute)
        # Cloud Tasks sends the token with audience = target_url
        expected_audience = f"{SERVICE_URL}/execute"
        if not SERVICE_URL:
            logger.error("SERVICE_URL not set, cannot verify audience")
            return False

        id_info = id_token.verify_oauth2_token(token, google_requests.Request(), audience=expected_audience)

        logger.info(f"Verified OIDC token for {id_info.get('email')} with audience {id_info.get('aud')}")
        return True
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        return False

def get_runbooks():
    """Scans the runbooks directory and extracts metadata."""
    runbooks = []
    runbooks_dir = os.path.join(os.getcwd(), 'runbooks')

    if not os.path.exists(runbooks_dir):
        return runbooks

    for filename in os.listdir(runbooks_dir):
        if filename.endswith(".sh"):
            filepath = os.path.join(runbooks_dir, filename)
            action = filename[:-3] # remove .sh
            description = "No description provided."
            params = []

            try:
                with open(filepath, 'r') as f:
                    for line in f:
                        if line.startswith("# DESC:"):
                            description = line[7:].strip()
                        elif line.startswith("# REQ:"):
                            # Format: # REQ: param_name (Label Text)
                            match = re.search(r'# REQ:\s*(\w+)\s*(?:\((.*)\))?', line)
                            if match:
                                param_name = match.group(1)
                                label = match.group(2) if match.group(2) else param_name
                                params.append({"name": param_name, "label": label})
            except Exception as e:
                logger.error(f"Error reading {filename}: {e}")
                continue

            runbooks.append({
                "action": action,
                "description": description,
                "params": params
            })
    return runbooks

@app.route('/login')
def login():
    if not os.environ.get("GOOGLE_CLIENT_ID"):
        return "Google Client ID not configured", 500
    redirect_uri = url_for('auth', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth')
def auth():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        # If userinfo is missing from token (sometimes happens depending on scope/response), fetch it
        if not user_info:
             user_info = google.userinfo()

        session['user'] = user_info
        return redirect('/')
    except Exception as e:
        logger.error(f"Auth failed: {e}")
        return f"Authentication failed: {e}", 400

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

@app.route('/', methods=['GET'])
@login_required
def index():
    """Renders the Portal UI."""
    runbooks = get_runbooks()
    return render_template('index.html', runbooks=runbooks, project_id=PROJECT_ID, user=session.get('user'))

@app.route('/enqueue', methods=['POST'])
@login_required
def enqueue_task():
    """Enqueues a task to Cloud Tasks."""
    data = request.form.to_dict()
    action = data.get('action')

    if not action:
        return "Missing action", 400

    # Validate Configuration
    if PROJECT_ID == "unknown-project":
        logger.error("PROJECT_ID environment variable is missing.")
        return "Configuration Error: PROJECT_ID not set on server.", 500

    # Clean up form data to be just the params for the payload
    payload = data.copy()

    # Ensure PROJECT_ID is passed if not in form (though form usually overrides)
    # The UI should map the user input to the variable names

    # Construct Cloud Task
    client = tasks_v2.CloudTasksClient()
    logger.info(f"Enqueuing task to: projects/{PROJECT_ID}/locations/{REGION}/queues/{QUEUE_NAME}")
    parent = client.queue_path(PROJECT_ID, REGION, QUEUE_NAME)

    # If SERVICE_URL is not set, we can't properly target ourselves
    target_url = SERVICE_URL
    if not target_url:
        # Fallback for local testing or misconfig
        logger.warning("SERVICE_URL env var not set. Task might fail if not fully configured.")
        target_url = "http://localhost:8080/execute" # Placeholder

    # The worker expects a JSON payload with 'action' and 'project_id' (legacy)
    # and any other params as environment variables?
    # Actually, the original worker logic put 'project_id' into env.
    # We should update the worker logic to put ALL payload keys into env.

    task = {
        "http_request": {
            "http_method": tasks_v2.HttpMethod.POST,
            "url": f"{target_url}/execute",
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(payload).encode(),
        }
    }

    if SERVICE_ACCOUNT_EMAIL:
         task["http_request"]["oidc_token"] = {
             "service_account_email": SERVICE_ACCOUNT_EMAIL
         }

    try:
        response = client.create_task(request={"parent": parent, "task": task})
        logger.info(f"Created task {response.name}")
        return render_template('success.html', task_name=response.name)
    except Exception as e:
        logger.exception("Failed to create task")
        return f"Error creating task: {e}", 500

@app.route('/execute', methods=['POST'])
def execute_runbook():
    """The Worker Endpoint. Executes the bash script."""

    # Security: Verify OIDC Token
    # Since we are using --allow-unauthenticated, we MUST verify the token here
    if not verify_oidc_token():
        return "Unauthorized: Invalid or Missing Token", 401

    # Input validation
    try:
        payload = request.get_json(force=True)
    except Exception:
        return "Invalid JSON", 400

    action = payload.get('action')
    if not action:
        return "Missing 'action'", 400

    # Sanitize action
    if '..' in action or '/' in action:
         logger.warning(f"Invalid action name attempt: {action}")
         return "Invalid action name", 400

    script_path = os.path.join(os.getcwd(), 'runbooks', f"{action}.sh")
    if not os.path.exists(script_path):
        logger.error(f"Runbook not found: {script_path}")
        return f"Runbook '{action}' not found", 404

    logger.info(f"Executing {action} with payload {payload}")

    # Prepare Environment
    env = os.environ.copy()
    # Inject all payload keys as environment variables
    # (e.g., project_id -> PROJECT_ID)
    injected_keys = []
    for key, value in payload.items():
        env_key = key.upper()
        env[env_key] = str(value)
        injected_keys.append(env_key)

    logger.info(f"Injected environment variables: {injected_keys}")

    try:
        result = subprocess.run(
            [script_path],
            env=env,
            capture_output=True,
            text=True,
            check=False
        )

        # Log Output
        logger.info(f"--- Output for {action} ---")
        for line in result.stdout.splitlines():
            logger.info(line)

        if result.stderr:
            logger.error(f"--- Error for {action} ---")
            for line in result.stderr.splitlines():
                logger.error(line)

        if result.returncode == 0:
            return "Success", 200
        else:
            return f"Script failed with exit code {result.returncode}", 500

    except Exception as e:
        logger.exception(f"Execution error: {e}")
        return str(e), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
