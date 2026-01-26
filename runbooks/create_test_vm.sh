#!/bin/bash
# DESC: Creates a cheap f1-micro VM in the default network for connectivity testing.
# REQ: project_id (Target Project ID)
# REQ: zone (Zone [default: us-central1-a])
set -e

if [ -z "$PROJECT_ID" ]; then
  echo "Error: PROJECT_ID environment variable is not set."
  exit 1
fi

ZONE="${ZONE:-us-central1-a}"
VM_NAME="test-vm-f1-micro"

echo "Processing project: $PROJECT_ID"
echo "Target Zone: $ZONE"

# Check if VM exists
if gcloud compute instances describe "$VM_NAME" --project="$PROJECT_ID" --zone="$ZONE" > /dev/null 2>&1; then
    echo "VM '$VM_NAME' already exists in $ZONE."
else
    echo "Creating VM '$VM_NAME' in $ZONE..."
    gcloud compute instances create "$VM_NAME" \
        --project="$PROJECT_ID" \
        --zone="$ZONE" \
        --machine-type=f1-micro \
        --image-family=debian-11 \
        --image-project=debian-cloud \
        --network-interface=subnet=default,no-address \
        --quiet
    echo "VM '$VM_NAME' created successfully."
fi
