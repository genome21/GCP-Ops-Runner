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

2.  **Configuration (Optional):**
    By default, resources are deployed to `us-central1`. You can override this by setting the `REGION` environment variable.

    ```bash
    export REGION=us-east1
    ```

3.  **Deploy Infrastructure:**
    Run the setup script to enable APIs, create the service account, queue, and deploy the Cloud Run service.

    ```bash
    ./deploy/setup_infra.sh
    ```

    This script will:
    *   Enable required APIs (Cloud Run, Cloud Tasks, IAM, etc.).
    *   Create a Service Account (`ops-runner-sa`).
    *   Grant **Project IAM Admin**, **Cloud Run Invoker**, and **Cloud Tasks Enqueuer** roles.
    *   Create a Cloud Tasks queue (`ops-queue`).
    *   Deploy the Cloud Run service (`ops-runner`).

    > **⚠️ Security Warning:** The `setup_infra.sh` script grants `roles/resourcemanager.projectIamAdmin` to the Runner Service Account. This is a high-privilege role designed to allow the runner to fix IAM permissions. For a production environment, you should restrict this Service Account's permissions to the minimum required for your specific runbooks.

4.  **Accessing the UI:**
    The Cloud Run service is deployed securely (`--no-allow-unauthenticated`). To access the Ops Portal UI, you have two options:

    *   **Option A: Identity-Aware Proxy (Recommended for Production)**
        To securely expose the UI to your internal team, set up [Identity-Aware Proxy (IAP) for Cloud Run](https://cloud.google.com/iap/docs/enabling-cloud-run). This requires configuring an HTTPS Load Balancer and OAuth credentials, which are outside the scope of the setup script.

    *   **Option B: Local Proxy (For Testing)**
        You can proxy the service to your local machine using `gcloud`:
        ```bash
        gcloud run services proxy ops-runner --project=YOUR_PROJECT_ID --port=8080
        ```
        Then visit `http://localhost:8080` in your browser.

## Usage

### 1. Web Portal (Recommended)

Navigate to the Cloud Run Service URL (if IAP configured) or `http://localhost:8080` (if using proxy).
1.  Select a runbook from the list.
2.  Fill in the required parameters (parsed from the runbook header).
3.  Click **Execute Runbook** to queue the task.

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

## Logging

The runner is configured to stream logs to Cloud Logging.
- Standard output (stdout) from runbooks is logged at `INFO` level.
- Standard error (stderr) from runbooks is logged at `ERROR` level.

## Security

*   **Isolation:** Runbooks execute in a serverless container.
*   **Authentication:** The Cloud Run service only accepts authenticated requests (OIDC) from the allowed Service Account.
*   **Least Privilege:** The Runner Service Account should only have the permissions necessary for the runbooks. The default setup grants `Project IAM Admin` for demonstration purposes; audit and scope this down for your needs.
