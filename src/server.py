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
from google.cloud import firestore

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

# Initialize Firestore
try:
    db = firestore.Client(project=PROJECT_ID)
except Exception as e:
    logger.warning(f"Failed to initialize Firestore: {e}. Rules engine will not work.")
    db = None

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

@app.route('/setup', methods=['GET'])
@login_required
def setup_helper():
    """Renders the Setup Helper UI."""
    return render_template('setup_helper.html', project_id=PROJECT_ID, user=session.get('user'))

@app.route('/rules', methods=['GET'])
@login_required
def rules_list():
    """Renders the Rules Management UI."""
    if not db:
        return "Firestore not configured.", 500

    rules = []
    try:
        docs = db.collection('automation_rules').stream()
        for doc in docs:
            rule = doc.to_dict()
            rule['id'] = doc.id
            rules.append(rule)
    except Exception as e:
        logger.error(f"Error fetching rules: {e}")
        return f"Error fetching rules: {e}", 500

    return render_template('rules.html', rules=rules, user=session.get('user'))

@app.route('/rules/add', methods=['POST'])
@login_required
def add_rule():
    if not db:
        return "Firestore not configured.", 500

    rule_name = request.form.get('rule_name', 'Unnamed Rule')
    label_key = request.form.get('label_key')
    label_value = request.form.get('label_value')
    groups_str = request.form.get('target_groups') # Comma separated

    if not label_key or not label_value or not groups_str:
        return "Missing fields", 400

    target_groups = [g.strip() for g in groups_str.split(',') if g.strip()]

    try:
        db.collection('automation_rules').add({
            'name': rule_name,
            'label_key': label_key,
            'label_value': label_value,
            'target_groups': target_groups
        })
        return redirect('/rules')
    except Exception as e:
        return f"Error adding rule: {e}", 500

@app.route('/rules/delete', methods=['POST'])
@login_required
def delete_rule():
    if not db:
        return "Firestore not configured.", 500

    rule_id = request.form.get('rule_id')
    if not rule_id:
        return "Missing rule_id", 400

    try:
        db.collection('automation_rules').document(rule_id).delete()
        return redirect('/rules')
    except Exception as e:
        return f"Error deleting rule: {e}", 500

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

        method_name = data.get("protoPayload", {}).get("methodName")
        if method_name != "CreateProject":
             logger.info(f"Ignored event method: {method_name}")
             return "Ignored", 200

        target_project_id = data.get("resource", {}).get("labels", {}).get("project_id")

        if not target_project_id:
             logger.error("Could not determine project_id from event")
             return "Error: No Project ID", 400

        logger.info(f"New Project Detected: {target_project_id}")

        # Get Labels
        credentials, _ = google.auth.default()
        service = discovery.build('cloudresourcemanager', 'v3', credentials=credentials)
        project = service.projects().get(name=f"projects/{target_project_id}").execute()
        labels = project.get("labels", {})

        # Rules Engine Logic
        if not db:
            logger.warning("Firestore not configured. Skipping Rules Engine.")
            return "Skipped (No DB)", 200

        # Fetch all rules (simplification for scale)
        rules_ref = db.collection('automation_rules')
        rules = rules_ref.stream()

        triggered_count = 0

        for rule_doc in rules:
            rule = rule_doc.to_dict()
            rule_name = rule.get('name', rule_doc.id)
            label_key = rule.get('label_key')
            label_value = rule.get('label_value')
            target_groups = rule.get('target_groups', [])

            # Check for match
            # Match if label key exists and value matches
            # OR if label key exists and rule value is "*" (wildcard support optional, not requested but good)
            # User requirement: "if a particular project label equals something like gcp-adv"
            # Implies Key=Value check.

            project_label_value = labels.get(label_key)

            if project_label_value == label_value:
                logger.info(f"Rule '{rule_name}' ({rule_doc.id}) matched for {label_key}={label_value}")

                for group_tmpl in target_groups:
                    # Resolve Template
                    # Supports {project_id}, {domain}
                    try:
                        group_email = group_tmpl.format(project_id=target_project_id, domain=DOMAIN)
                    except KeyError as e:
                        logger.error(f"Rule {rule_doc.id} template error: Missing key {e} in template '{group_tmpl}'")
                        continue
                    except Exception as e:
                        logger.error(f"Rule {rule_doc.id} template formatting error: {e}")
                        continue

                    logger.info(f"Triggering add_group_to_project for {group_email}")

                    payload = {
                        "action": "add_group_to_project",
                        "project_id": target_project_id,
                        "group_email": group_email
                    }
                    create_task("add_group_to_project", payload)
                    triggered_count += 1

        return f"Triggered {triggered_count} tasks", 200

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
