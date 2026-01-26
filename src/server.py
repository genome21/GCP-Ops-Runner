import os
import json
import subprocess
import sys
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler

# Configure logging to output JSON for Google Cloud Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

class RunnerHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)

        try:
            payload = json.loads(post_data)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON")
            logger.error("Received invalid JSON payload")
            return

        action = payload.get('action')
        project_id = payload.get('project_id')

        if not action or not project_id:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing 'action' or 'project_id'")
            logger.error("Missing 'action' or 'project_id' in payload")
            return

        # Sanitize action to prevent directory traversal
        if '..' in action or '/' in action:
             self.send_response(400)
             self.end_headers()
             self.wfile.write(b"Invalid action name")
             logger.warning(f"Invalid action name attempt: {action}")
             return

        # Assuming the script runs from /app, runbooks are in /app/runbooks
        # Or relative to current working directory
        script_path = os.path.join(os.getcwd(), 'runbooks', f"{action}.sh")

        if not os.path.exists(script_path):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(f"Runbook '{action}' not found".encode())
            logger.error(f"Runbook not found: {script_path}")
            return

        logger.info(f"Executing {action} for project {project_id}")

        env = os.environ.copy()
        env['PROJECT_ID'] = project_id

        try:
            result = subprocess.run(
                [script_path],
                env=env,
                capture_output=True,
                text=True,
                check=False
            )

            logger.info(f"--- Output for {action} ---")
            for line in result.stdout.splitlines():
                logger.info(line)

            if result.stderr:
                logger.error(f"--- Error for {action} ---")
                for line in result.stderr.splitlines():
                    logger.error(line)

            if result.returncode == 0:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Success")
                logger.info(f"Runbook {action} completed successfully.")
            else:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Script failed with exit code {result.returncode}".encode())
                logger.error(f"Runbook {action} failed with exit code {result.returncode}")

        except Exception as e:
            logger.exception(f"Execution error: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def do_GET(self):
        # Health check
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

def run(server_class=HTTPServer, handler_class=RunnerHandler):
    port = int(os.environ.get('PORT', 8080))
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logger.info(f"Starting server on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
