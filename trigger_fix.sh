#!/bin/bash
set -e

ACTION=$1
TARGET_PROJECT_ID=$2

if [ -z "$ACTION" ] || [ -z "$TARGET_PROJECT_ID" ]; then
    echo "Usage: $0 <action> <target_project_id>"
    echo "Example: $0 restore_compute_editor my-project-id"
    exit 1
fi

PROJECT_ID=$(gcloud config get-value project)
REGION="${REGION:-us-central1}"
QUEUE_NAME="ops-queue"
SERVICE_NAME="ops-runner"
SA_NAME="ops-runner-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "Fetching Service URL..."
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --region "$REGION" --format='value(status.url)')

if [ -z "$SERVICE_URL" ]; then
    echo "Error: Cloud Run service url not found."
    exit 1
fi

echo "Service URL: $SERVICE_URL"

PAYLOAD="{\"action\": \"$ACTION\", \"project_id\": \"$TARGET_PROJECT_ID\"}"
echo "Payload: $PAYLOAD"

echo "Creating Task..."
gcloud tasks create-http-task \
    --queue="$QUEUE_NAME" \
    --location="$REGION" \
    --url="$SERVICE_URL" \
    --header="Content-Type: application/json" \
    --body-content="$PAYLOAD" \
    --oidc-service-account-email="$SA_EMAIL"

echo "Task created successfully."
