#!/bin/bash
# DESC: A simple test script to verify the system works.
# REQ: project_id (Target Project ID)
set -e

echo "Hello from Ops Runner!"
echo "Target Project ID: ${PROJECT_ID:-Unknown}"
echo "Action executed successfully."
