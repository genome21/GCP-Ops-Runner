# GCP Ops Automation Framework

A serverless execution framework for Google Cloud operational runbooks. Uses Bash + `gcloud` via Cloud Run and Cloud Tasks to provide a safe, auditable, and repeatable remediation interface for Ops teams.

## Architecture

1.  **Trigger:** Cloud Tasks (asynchronous queue).
2.  **Execution:** Cloud Run (Dispatcher) running a `google/cloud-sdk:slim` container.
3.  **Runbook Logic:** Bash scripts located in `/runbooks`.

## Directory Structure

*   `runbooks/`: Contains the automation scripts (e.g., `restore_compute_editor.sh`).
*   `src/`: Contains the dispatcher logic (`server.py`, `runner.sh`) and `Dockerfile`.
*   `deploy/`: Contains infrastructure setup scripts.
*   `trigger_fix.sh`: CLI helper to trigger a runbook.

## Setup & Deployment

1.  **Prerequisites:**
    *   Google Cloud SDK (`gcloud`) installed and authenticated.
    *   Appropriate permissions to create projects, service accounts, and Cloud Run services.

2.  **Deploy Infrastructure:**
    Run the setup script to enable APIs, create the service account, queue, and deploy the Cloud Run service.

    ```bash
    ./deploy/setup_infra.sh
    ```

    This script will:
    *   Enable required APIs (Cloud Run, Cloud Tasks, IAM, etc.).
    *   Create a Service Account (`ops-runner-sa`).
    *   Grant `Project IAM Admin` and `Cloud Run Invoker` roles.
    *   Create a Cloud Tasks queue (`ops-queue`).
    *   Deploy the Cloud Run service (`ops-runner`).

## Usage

### Triggering a Runbook

Use the `trigger_fix.sh` script to enqueue a task. This allows Ops users to trigger fixes without needing direct IAM permissions on the target project.

```bash
./trigger_fix.sh <action_name> <target_project_id>
```

**Example:**

To restore the `roles/editor` role to the default Compute Engine service account in project `my-target-project`:

```bash
./trigger_fix.sh restore_compute_editor my-target-project
```

### Adding New Runbooks

1.  Create a new `.sh` script in the `runbooks/` directory.
2.  Ensure the script uses `PROJECT_ID` (passed as an environment variable) to target the correct project.
3.  Re-deploy the Cloud Run service (or use a build pipeline) to include the new script.

    ```bash
    gcloud run deploy ops-runner --source . --platform managed --region us-central1 --quiet
    ```

## Security

*   **Isolation:** Runbooks execute in a serverless container.
*   **Authentication:** The Cloud Run service only accepts authenticated requests (OIDC) from the allowed Service Account.
*   **Least Privilege:** The Runner Service Account should only have the permissions necessary for the runbooks (currently `Project IAM Admin`).
