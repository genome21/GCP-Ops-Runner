#!/bin/bash
# DESC: Restores the roles/editor role to the default Compute Engine Service Account.
# REQ: project_id (Target Project ID)
set -e

if [ -z "$PROJECT_ID" ]; then
  echo "Error: PROJECT_ID environment variable is not set."
  exit 1
fi

echo "Processing project: $PROJECT_ID"

# Get Project Number
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format="value(projectNumber)")
echo "Project Number: $PROJECT_NUMBER"

COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
echo "Compute Service Account: $COMPUTE_SA"

# Check if role exists
EXISTING_BINDING=$(gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.role:roles/editor AND bindings.members:serviceAccount:$COMPUTE_SA" \
  --format="value(bindings.role)")

if [ "$EXISTING_BINDING" == "roles/editor" ]; then
  echo "Success: $COMPUTE_SA already has roles/editor in $PROJECT_ID."
else
  echo "Warning: $COMPUTE_SA is missing roles/editor. Restoring..."
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$COMPUTE_SA" \
    --role="roles/editor"
  echo "Restored roles/editor to $COMPUTE_SA."
fi
