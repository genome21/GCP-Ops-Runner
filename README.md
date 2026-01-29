# GCP Ops Automation Framework

A serverless execution framework for Google Cloud operational runbooks. Features a user-friendly **Web UI ("Ops Portal")** for safe, self-service remediation. Uses Bash + `gcloud` via Cloud Run and Cloud Tasks to separate intent from execution.

![Ops Portal UI](docs/images/portal.png)

## Architecture

1.  **Trigger:** Cloud Tasks (asynchronous queue).
2.  **Execution:** Cloud Run (Dispatcher) running a `google/cloud-sdk:slim` container.
3.  **Runbook Logic:** Bash scripts located in `/runbooks`.

## Directory Structure

*   `runbooks/`: Contains the automation scripts (e.g., `hello_world.sh`, `create_test_vm.sh`).
*   `src/`: Contains the dispatcher logic (`server.py`, `runner.sh`) and `Dockerfile`.
*   `deploy/`: Contains infrastructure setup scripts.
*   `trigger_fix.sh`: CLI helper to trigger a runbook.

## Setup & Deployment

1.  **Prerequisites:**
    *   Google Cloud SDK (`gcloud`) installed and authenticated.
    *   Appropriate permissions to create projects, service accounts, and Cloud Run services.

2.  **Google Sign-In Setup:**
    The Ops Portal uses Google Sign-In to authenticate users. You must create OAuth credentials in the Google Cloud Console:
    1.  Go to **APIs & Services > Credentials**.
    2.  Click **Create Credentials > OAuth client ID**.
    3.  Application Type: **Web application**.
    4.  Name: `Ops Portal`.
    5.  **Authorized Redirect URIs:** You will need to add the Cloud Run Service URL + `/auth` after deployment (e.g., `https://ops-runner-xyz.a.run.app/auth`). For now, you can leave it blank or put a placeholder.
    6.  **User Type:** Choose **Internal** if you want to restrict access to users within your Google Workspace organization. Choose **External** (and set to 'Testing') if you need to allow specific external users (requires adding them as Test Users).
    7.  Copy the **Client ID** and **Client Secret**.

3.  **Deploy Infrastructure:**
    Export your credentials and region, then run the setup script.

    ```bash
    export REGION=us-central1
    export GOOGLE_CLIENT_ID="your-client-id"
    export GOOGLE_CLIENT_SECRET="your-client-secret"
    export DOMAIN="example.com" # Your Identity Domain for group sync

    ./deploy/setup_infra.sh
    ```

    *Note: After deployment, copy the Service URL printed at the end and add it to the "Authorized Redirect URIs" in the GCP Console (append `/auth` to the URL).*

    This script will:
    *   Enable required APIs.
    *   Create a Service Account (`ops-runner-sa`).
    *   Grant **Project IAM Admin**, **Cloud Run Invoker**, and **Cloud Tasks Enqueuer** roles.
    *   Create a Cloud Tasks queue (`ops-queue`).
    *   Deploy the Cloud Run service (`ops-runner`) with **public access** enabled (authentication is enforced by the application).
    *   Create an **EventArc Trigger** to listen for Project Creation events and automatically sync groups if applicable.

    > **⚠️ Security Warning:** The `setup_infra.sh` script grants `roles/resourcemanager.projectIamAdmin` to the Runner Service Account. This is a high-privilege role designed to allow the runner to fix IAM permissions. For a production environment, you should restrict this Service Account's permissions to the minimum required for your specific runbooks.

## Usage

### 1. Web Portal (Recommended)

Navigate to the Cloud Run Service URL.
1.  You will be redirected to Google Sign-In. Log in with your Google account.
2.  Select a runbook from the list.
3.  Fill in the required parameters (parsed from the runbook header).
4.  Click **Execute Runbook** to queue the task.

### 2. CLI Trigger

Use the `trigger_fix.sh` script to enqueue a task. This allows Ops users to trigger fixes without needing direct IAM permissions on the target project.

```bash
./trigger_fix.sh <action_name> <target_project_id>
```

**Example 1: Hello World**

To test the system with a safe, read-only runbook:

```bash
./trigger_fix.sh hello_world my-target-project
```

**Example 2: Create Test VM**

To create a cheap f1-micro VM for testing (requires Compute Engine API enabled on target project):

```bash
./trigger_fix.sh create_test_vm my-target-project
```

### Adding New Runbooks

See the [Runbook Development Guide](RUNBOOK_GUIDE.md) for detailed instructions on creating, testing, and deploying new runbooks.

1.  Create a new `.sh` script in the `runbooks/` directory.
2.  Add metadata headers for the UI:
    ```bash
    # DESC: Description of what the script does.
    # REQ: variable_name (Label for UI)
    ```
3.  Ensure the script uses the variable names (passed as environment variables) to target the correct resources.
4.  Re-deploy the Cloud Run service (or use a build pipeline) to include the new script.

    ```bash
    gcloud run deploy ops-runner --source . --platform managed --region ${REGION:-us-central1} --quiet
    ```

## Event-Driven Automation

The framework supports reacting to GCP events via EventArc.

### Use Case: Dynamic Group Sync (Rules Engine)

The framework includes a **Rules Engine** (backed by Firestore) that allows you to define dynamic automation rules via the Web UI.

1.  **Trigger:** `google.cloud.resourcemanager.project.v1.create` (via Cloud Audit Logs).
2.  **Evaluation:** The system checks the new project's labels against the rules defined in Firestore.
3.  **Action:** If a rule matches (e.g., Label Key `type` == `gcp-adv`), the system iterates through the configured **Target Group Templates**.
    *   Example Template: `{project_id}-admins@{domain}`
    *   **Available Variables:** `{project_id}`, `{domain}`
    *   The system resolves the template variables and triggers the `add_group_to_project` runbook for each group.
4.  **Retry:** If the group does not exist yet (e.g., syncing from Azure AD), the runbook exits with error, causing Cloud Tasks to retry until success.

**Managing Rules:**
Access the "Rules Engine" from the Ops Portal navigation bar to Add/Delete rules dynamically without changing code.

## Logging

The runner is configured to stream logs to Cloud Logging.
- Standard output (stdout) from runbooks is logged at `INFO` level.
- Standard error (stderr) from runbooks is logged at `ERROR` level.

## Security

*   **Isolation:** Runbooks execute in a serverless container.
*   **Authentication:**
    *   **User Access:** Protected by Google Sign-In (OAuth 2.0).
    *   **Authorization:** The application enforces authorization by checking if the signed-in user has the `roles/iap.httpsResourceAccessor` role on the project. This mimics IAP behavior at the application level.
    *   **Task Execution:** Protected by OIDC Token Verification. The worker endpoint `/execute` validates that the request comes from a trusted Service Account via Cloud Tasks.
*   **Least Privilege:** The Runner Service Account should only have the permissions necessary for the runbooks. The default setup grants `Project IAM Admin` for demonstration purposes; audit and scope this down for your needs.

## Troubleshooting

### Google Sign-In "Access Blocked"
If you see an error saying "Access blocked: [App Name] can only be used within its organization":
*   This means your OAuth Consent Screen is set to **Internal**, but you are trying to sign in with an account *outside* the Google Workspace organization that owns the project.
*   **Solution:** Sign in with an account from the same organization, or change the User Type to **External** (and add your email as a Test User) in the Google Cloud Console.
