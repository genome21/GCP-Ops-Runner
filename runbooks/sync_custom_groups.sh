#!/bin/bash
# DESC: Syncs custom Azure AD groups to the project if available. Retries until sync is complete.
# REQ: project_id (Target Project ID)
# REQ: domain (Identity Domain, e.g. example.com)

set -e

if [ -z "$PROJECT_ID" ] || [ -z "$DOMAIN" ]; then
  echo "Error: PROJECT_ID or DOMAIN environment variable is not set."
  exit 1
fi

GROUP_EMAIL="${PROJECT_ID}-application-team@${DOMAIN}"

echo "Checking for group: $GROUP_EMAIL"

# Check if group exists in Cloud Identity
# We use || true to prevent set -e from exiting on failure, capture output
# Note: gcloud identity groups describe requires Group Reader permissions
if gcloud identity groups describe "$GROUP_EMAIL" > /dev/null 2>&1; then
    echo "Group $GROUP_EMAIL found."

    # Add IAM binding
    echo "Granting roles/viewer to $GROUP_EMAIL on $PROJECT_ID..."
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="group:$GROUP_EMAIL" \
        --role="roles/viewer" \
        --condition=None

    echo "Success: Group synced and permissions granted."
    exit 0
else
    echo "Group $GROUP_EMAIL not found yet. It may be syncing from Azure AD."
    echo "Exiting with error to trigger Cloud Task retry..."
    exit 1
fi
