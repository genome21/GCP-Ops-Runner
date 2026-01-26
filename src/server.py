import os
import json
import subprocess
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

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
            return

        action = payload.get('action')
        project_id = payload.get('project_id')

        if not action or not project_id:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing 'action' or 'project_id'")
            return

        # Sanitize action to prevent directory traversal
        if '..' in action or '/' in action:
             self.send_response(400)
             self.end_headers()
             self.wfile.write(b"Invalid action name")
             return

        # Assuming the script runs from /app, runbooks are in /app/runbooks
        # Or relative to current working directory
        script_path = os.path.join(os.getcwd(), 'runbooks', f"{action}.sh")

        if not os.path.exists(script_path):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(f"Runbook '{action}' not found".encode())
            print(f"Runbook {script_path} not found")
            return

        print(f"Executing {action} for project {project_id}")

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

            print(f"--- Output for {action} ---")
            print(result.stdout)
            if result.stderr:
                print(f"--- Error for {action} ---", file=sys.stderr)
                print(result.stderr, file=sys.stderr)

            if result.returncode == 0:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Success")
            else:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Script failed with exit code {result.returncode}".encode())

        except Exception as e:
            print(f"Execution error: {e}", file=sys.stderr)
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
    print(f"Starting server on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
