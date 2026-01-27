# Runbook Development Guide

This guide explains how to create, test, and deploy new automation runbooks for the GCP Ops Automation Framework.

## Runbook Anatomy

Runbooks are simple Bash scripts located in the `runbooks/` directory. The framework uses special comments in the script header to generate the Ops Portal UI.

### 1. Metadata Headers

The Ops Portal scans the first few lines of each script for metadata:

*   `# DESC:` A short description of what the runbook does. This is displayed on the runbook card in the UI.
*   `# REQ:` Defines a required input variable. The UI will generate a form field for each requirement.
    *   **Format:** `# REQ: variable_name (Label Text)`
    *   **Example:** `# REQ: project_id (Target Project ID)`

### 2. Variable Usage

When a user submits the form in the Ops Portal, the input values are passed to the Bash script as **Environment Variables**.

*   Variable names are automatically converted to **UPPERCASE**.
*   Example: An input defined as `# REQ: project_id` will be available in the script as `$PROJECT_ID`.
*   Example: An input defined as `# REQ: target_zone` will be available as `$TARGET_ZONE`.

### Example Script

Create a file named `runbooks/example_task.sh`:

```bash
#!/bin/bash
# DESC: Updates a label on a GCS bucket.
# REQ: project_id (Project ID)
# REQ: bucket_name (Bucket Name)
# REQ: label_value (New Label Value)

set -e

# Validate inputs (Recommended)
if [ -z "$PROJECT_ID" ] || [ -z "$BUCKET_NAME" ]; then
  echo "Error: Missing required variables."
  exit 1
fi

echo "Starting task for project: $PROJECT_ID"

# Perform the operation
gcloud storage buckets update "gs://$BUCKET_NAME" \
    --project="$PROJECT_ID" \
    --update-labels="environment=$LABEL_VALUE"

echo "Successfully updated label on gs://$BUCKET_NAME"
```

## Adding & Deploying Runbooks

1.  **Create the Script:** Save your `.sh` file in the `runbooks/` directory of this repository.
2.  **Make Executable:** Ensure the script has execute permissions (locally):
    ```bash
    chmod +x runbooks/your_script.sh
    ```
3.  **Test Locally (Optional):** You can test the script manually by exporting the expected variables:
    ```bash
    export PROJECT_ID=my-test-project
    export BUCKET_NAME=my-bucket
    ./runbooks/example_task.sh
    ```
4.  **Deploy:** To make the runbook available in the Ops Portal, you must re-deploy the Cloud Run service. This packages the new script into the container image.

    ```bash
    # Ensure you are in the root of the repo
    gcloud run deploy ops-runner \
        --source . \
        --platform managed \
        --region us-central1 \
        --quiet
    ```

    *Note: If you configured a custom region during setup, replace `us-central1` with your region.*

5.  **Verify:** Visit the Ops Portal URL. You should see a new card for your runbook. clicking "Select Runbook" will show the form fields corresponding to your `# REQ` headers.
