#!/bin/bash
set -e

PROJECT_ID=$(gcloud config get-value project)
REGION="${REGION:-us-central1}"
SERVICE_NAME="ops-runner"
SA_NAME="ops-runner-sa"
QUEUE_NAME="ops-queue"

# Credentials for Google Sign-In
# You can set these before running the script
GOOGLE_CLIENT_ID="${GOOGLE_CLIENT_ID:-placeholder_client_id}"
GOOGLE_CLIENT_SECRET="${GOOGLE_CLIENT_SECRET:-placeholder_client_secret}"
FLASK_SECRET_KEY="${FLASK_SECRET_KEY:-$(openssl rand -hex 16)}"
DOMAIN="${DOMAIN:-example.com}"

echo "Deploying to Project: $PROJECT_ID in Region: $REGION"

# Enable APIs
echo "Enabling APIs..."
gcloud services enable run.googleapis.com cloudtasks.googleapis.com cloudbuild.googleapis.com iam.googleapis.com cloudresourcemanager.googleapis.com eventarc.googleapis.com cloudidentity.googleapis.com firestore.googleapis.com

# Create Service Account
echo "Creating Service Account..."
if ! gcloud iam service-accounts describe "${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" > /dev/null 2>&1; then
    gcloud iam service-accounts create "$SA_NAME" --display-name="Ops Runner Service Account"
fi

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# Grant permissions
echo "Granting Project IAM Admin..."
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/resourcemanager.projectIamAdmin"

echo "Granting Cloud Run Invoker (project level)..."
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/run.invoker"

echo "Granting Cloud Tasks Enqueuer..."
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/cloudtasks.enqueuer"

echo "Granting Datastore User (for Firestore)..."
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/datastore.user"

echo "Granting Service Account User (to allow OIDC token generation)..."
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/iam.serviceAccountUser"

# Grant Groups Reader (for sync_custom_groups.sh)
# Note: This might fail if the project isn't in an organization or if the user lacks permissions.
# Best effort attempt.
echo "Attempting to grant Groups Reader (best effort)..."
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/cloudidentity.groupsReader" || echo "Warning: Could not grant Groups Reader. Ensure SA has permissions to read Cloud Identity groups."

echo "Creating Firestore Database (if needed)..."
if ! gcloud firestore databases list --location="$REGION" --format="value(name)" | grep -q "projects/$PROJECT_ID/databases/(default)"; then
    gcloud firestore databases create --location="$REGION" --type=firestore-native --quiet || echo "Warning: Firestore creation might have failed or already exists."
fi

# EventArc Trigger Permissions
# The Trigger Identity (ops-runner-sa) needs to be able to invoke the Cloud Run service.
# We already granted roles/run.invoker to this SA above.

# Create Cloud Tasks Queue
echo "Creating Cloud Tasks Queue..."
if ! gcloud tasks queues describe "$QUEUE_NAME" --location="$REGION" > /dev/null 2>&1; then
    gcloud tasks queues create "$QUEUE_NAME" --location="$REGION"
fi

# Deploy Cloud Run Service
echo "Deploying Cloud Run Service..."
# Note: SERVICE_ACCOUNT_EMAIL must be explicitly exported or passed directly because it's a script variable, not an env var yet
# We switch to --allow-unauthenticated because authentication is now handled by the Application (Google Sign-In)
gcloud run deploy "$SERVICE_NAME" \
    --source . \
    --platform managed \
    --region "$REGION" \
    --service-account "$SA_EMAIL" \
    --allow-unauthenticated \
    --timeout=3600 \
    --set-env-vars "PROJECT_ID=${PROJECT_ID},REGION=${REGION},QUEUE_NAME=${QUEUE_NAME},SERVICE_ACCOUNT_EMAIL=${SA_EMAIL},GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID},GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET},FLASK_SECRET_KEY=${FLASK_SECRET_KEY},DOMAIN=${DOMAIN}" \
    --quiet

# EventArc Trigger for Project Creation
echo "Creating EventArc Trigger..."
# Trigger on Cloud Audit Logs for Project Creation
if ! gcloud eventarc triggers describe project-create-trigger --location="$REGION" > /dev/null 2>&1; then
    gcloud eventarc triggers create project-create-trigger \
        --location="$REGION" \
        --destination-run-service="$SERVICE_NAME" \
        --destination-run-region="$REGION" \
        --destination-run-path="/events/project-created" \
        --event-filters="type=google.cloud.audit.log.v1.written" \
        --event-filters="serviceName=cloudresourcemanager.googleapis.com" \
        --event-filters="methodName=CreateProject" \
        --service-account="$SA_EMAIL"
fi

# Fetch Service URL and update it as an env var (circular dependency workaround)
# The Service needs its own URL to know where to target the Task.
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --region "$REGION" --format='value(status.url)')
echo "Service URL: $SERVICE_URL"

echo "Updating Service with SERVICE_URL..."
gcloud run services update "$SERVICE_NAME" \
    --region "$REGION" \
    --update-env-vars="SERVICE_URL=$SERVICE_URL" \
    --quiet

echo "Setup complete."
echo "Service URL: $(gcloud run services describe $SERVICE_NAME --region $REGION --format='value(status.url)')"
