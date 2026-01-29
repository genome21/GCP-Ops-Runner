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
from googleapiclient import discovery
import google.auth
from cloudevents.http import from_http

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', stream=sys.stdout)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")
# Apply ProxyFix to handle HTTPS behind Cloud Run
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# OAuth Setup
oauth = OAuth(app)
google_oauth = oauth.register(
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
# Identity Domain for custom groups
DOMAIN = os.environ.get("DOMAIN", "example.com")

logger.info(f"Server starting with Config: PROJECT_ID={PROJECT_ID}, REGION={REGION}, QUEUE_NAME={QUEUE_NAME}, SERVICE_ACCOUNT_EMAIL={SERVICE_ACCOUNT_EMAIL}, DOMAIN={DOMAIN}")

def check_user_access(email):
    """
    Checks if the user has the 'roles/iap.httpsResourceAccessor' role on the project.
    """
    try:
        credentials, _ = google.auth.default()
        service = discovery.build('cloudresourcemanager', 'v1', credentials=credentials)

        policy = service.projects().getIamPolicy(resource=PROJECT_ID, body={}).execute()

        for binding in policy.get('bindings', []):
            if binding['role'] == 'roles/iap.httpsResourceAccessor':
                members = binding.get('members', [])
                if f"user:{email}" in members:
                    logger.info(f"User {email} authorized via IAM.")
                    return True

        logger.warning(f"User {email} NOT authorized. Missing roles/iap.httpsResourceAccessor")
        return False

    except Exception as e:
        logger.error(f"Error checking IAM permissions: {e}")
        return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))

        # Check authorization (cached in session)
        if not session.get('authorized'):
            return "Unauthorized: You do not have permission to access this portal.", 403

        return f(*args, **kwargs)
    return decorated_function

def verify_oidc_token(audience_override=None):
    """Verifies the Bearer token in the Authorization header."""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        logger.warning("Missing Authorization header in request")
        return False

    try:
        token = auth_header.split(" ")[1]

        # Determine expected audience
        # Cloud Tasks sends audience = target_url (e.g., .../execute)
        # EventArc sends audience = service_url (root)

        if not SERVICE_URL:
             logger.error("SERVICE_URL not set, cannot verify audience")
             return False

        if audience_override:
            allowed_audiences = [audience_override]
        else:
            # Allow both specific endpoint (Cloud Tasks) and root service (EventArc)
            allowed_audiences = [f"{SERVICE_URL}/execute", SERVICE_URL]

        # verify_oauth2_token doesn't support a list of audiences directly,
        # so we decode without audience verification first, check aud, then verify.
        # OR just try/except with each audience.

        # Simpler approach: Verify signature first, then check audience manually
        # But google library requires audience for verify_oauth2_token to be secure.

        # We will try verifying against the primary expected audience for the route
        # For this function, we default to the request.url or let caller specify.

        # Improved Strategy: The caller knows what endpoint they are protecting.
        # But we reused this function.
        # Let's iterate.

        verified_token = None
        last_error = None

        for aud in allowed_audiences:
            try:
                verified_token = id_token.verify_oauth2_token(token, google_requests.Request(), audience=aud)
                break
            except Exception as e:
                last_error = e

        if verified_token:
            logger.info(f"Verified OIDC token for {verified_token.get('email')} with audience {verified_token.get('aud')}")
            return True
        else:
            logger.error(f"Token verification failed for all allowed audiences: {allowed_audiences}. Last error: {last_error}")
            return False

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
    return google_oauth.authorize_redirect(redirect_uri)

@app.route('/auth')
def auth():
    try:
        token = google_oauth.authorize_access_token()
        user_info = token.get('userinfo')
        # If userinfo is missing from token (sometimes happens depending on scope/response), fetch it
        if not user_info:
             user_info = google_oauth.userinfo()

        email = user_info.get('email')
        if check_user_access(email):
            session['user'] = user_info
            session['authorized'] = True
            return redirect('/')
        else:
            return "Unauthorized: You do not have the required IAM role (roles/iap.httpsResourceAccessor).", 403

    except Exception as e:
        logger.error(f"Auth failed: {e}")
        return f"Authentication failed: {e}", 400

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('authorized', None)
    return redirect('/')

@app.route('/', methods=['GET'])
@login_required
def index():
    """Renders the Portal UI."""
    runbooks = get_runbooks()
    return render_template('index.html', runbooks=runbooks, project_id=PROJECT_ID, user=session.get('user'))

def create_task(action, payload):
    """Helper to create cloud task"""
    client = tasks_v2.CloudTasksClient()
    logger.info(f"Enqueuing task to: projects/{PROJECT_ID}/locations/{REGION}/queues/{QUEUE_NAME}")
    parent = client.queue_path(PROJECT_ID, REGION, QUEUE_NAME)

    target_url = SERVICE_URL
    if not target_url:
        logger.warning("SERVICE_URL env var not set.")
        target_url = "http://localhost:8080/execute" # Placeholder

    # Payload already has action and other params

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

    return client.create_task(request={"parent": parent, "task": task})


@app.route('/enqueue', methods=['POST'])
@login_required
def enqueue_task():
    """Enqueues a task to Cloud Tasks."""
    data = request.form.to_dict()
    action = data.get('action')

    if not action:
        return "Missing action", 400

    if PROJECT_ID == "unknown-project":
        logger.error("PROJECT_ID environment variable is missing.")
        return "Configuration Error: PROJECT_ID not set on server.", 500

    payload = data.copy()

    try:
        response = create_task(action, payload)
        logger.info(f"Created task {response.name}")
        return render_template('success.html', task_name=response.name)
    except Exception as e:
        logger.exception("Failed to create task")
        return f"Error creating task: {e}", 500

@app.route('/events/project-created', methods=['POST'])
def handle_project_created_event():
    """Handles EventArc trigger for Project Created event."""
    # Verify OIDC token from EventArc (which typically uses the Trigger SA)
    if not verify_oidc_token():
        return "Unauthorized", 401

    try:
        event = from_http(request.headers, request.get_data())
        data = event.data

        # Log the full event for debugging
        # logger.info(f"Received Event: {data}")

        # Check if it is a Project Create Audit Log
        # The structure depends on the Audit Log version.
        # Typically: protoPayload.methodName = "CreateProject"
        # resourceName = "projects/12345"

        method_name = data.get("protoPayload", {}).get("methodName")
        if method_name != "CreateProject":
             logger.info(f"Ignored event method: {method_name}")
             return "Ignored", 200

        resource_name = data.get("protoPayload", {}).get("resourceName")
        # Format: projects/PROJECT_ID (sometimes number, sometimes ID)
        # Actually CreateProject response typically has the Project Object.
        # Wait, CreateProject request might not have the ID if it's async?
        # Let's rely on resourceName or response.

        # Better: use the 'resource' field from the audit log
        # resource.type="project", resource.labels.project_id

        target_project_id = data.get("resource", {}).get("labels", {}).get("project_id")

        if not target_project_id:
             logger.error("Could not determine project_id from event")
             return "Error: No Project ID", 400

        logger.info(f"New Project Detected: {target_project_id}")

        # Check Labels
        credentials, _ = google.auth.default()
        service = discovery.build('cloudresourcemanager', 'v3', credentials=credentials)
        project = service.projects().get(name=f"projects/{target_project_id}").execute()

        labels = project.get("labels", {})
        # Check if ANY label has value "gcp-adv" OR key "gcp-adv"
        is_match = False
        for k, v in labels.items():
            if k == "gcp-adv" or v == "gcp-adv":
                is_match = True
                break

        if is_match:
            logger.info(f"Project {target_project_id} matches label criteria. Triggering sync.")
            # Trigger Task
            payload = {
                "action": "sync_custom_groups",
                "project_id": target_project_id,
                "domain": DOMAIN
            }
            create_task("sync_custom_groups", payload)
            return "Triggered", 200
        else:
            logger.info(f"Project {target_project_id} does not match label criteria.")
            return "Skipped", 200

    except Exception as e:
        logger.exception(f"Error processing event: {e}")
        return "Error", 500

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
