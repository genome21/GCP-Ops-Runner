#!/bin/bash
# DESC: Adds a specific Cloud Identity group to a project. Retries until available.
# REQ: group_email (Group Email Address)
# REQ: project_id (Target Project ID)
# REQ: role (IAM Role [default: roles/viewer])

set -e

ROLE="${ROLE:-roles/viewer}"

if [ -z "$PROJECT_ID" ] || [ -z "$GROUP_EMAIL" ]; then
  echo "Error: PROJECT_ID or GROUP_EMAIL environment variable is not set."
  exit 1
fi

echo "Checking for group: $GROUP_EMAIL"

# Check if group exists in Cloud Identity
# We use || true to prevent set -e from exiting on failure, capture output
if gcloud identity groups describe "$GROUP_EMAIL" > /dev/null 2>&1; then
    echo "Group $GROUP_EMAIL found."

    # Add IAM binding
    echo "Granting $ROLE to $GROUP_EMAIL on $PROJECT_ID..."
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="group:$GROUP_EMAIL" \
        --role="$ROLE" \
        --condition=None

    echo "Success: Group synced and permissions granted."
    exit 0
else
    echo "Group $GROUP_EMAIL not found yet. It may be syncing from Azure AD."
    echo "Exiting with error to trigger Cloud Task retry..."
    exit 1
fi
