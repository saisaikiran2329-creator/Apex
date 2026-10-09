import hmac
import json
import os
import secrets
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from http.cookies import CookieError, SimpleCookie
from urllib.parse import parse_qs, urlsplit


LOGIN_EMAIL = os.environ.get("LOGIN_EMAIL")
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
MAX_REQUEST_SIZE = 16_384
SESSION_TTL_SECONDS = 8 * 60 * 60
JOBS_FILE = Path(os.environ.get("JOBS_FILE", Path(__file__).with_name("jobs.json")))
ALLOWED_STATIC_EXTENSIONS = {".css", ".html", ".ico", ".jpeg", ".jpg", ".js", ".png", ".svg", ".webp"}
PROTECTED_PAGES = {"/login-success.html", "/post-jobs.html"}
sessions = {}
sessions_lock = threading.Lock()
jobs_lock = threading.Lock()


class WebsiteHandler(SimpleHTTPRequestHandler):
    def send_json(self, status, payload, extra_headers=None):
        response = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(response)

    def current_session(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None

        session_cookie = cookie.get("apex_session")
        if session_cookie is None:
            return None

        token = session_cookie.value
        with sessions_lock:
            expiry = sessions.get(token)
            if expiry is None:
                return None
            if expiry <= time.time():
                del sessions[token]
                return None
            return token

    def read_request_body(self):
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            return None

        if content_length <= 0:
            self.send_error(400, "Request body is required")
            return None
        if content_length > MAX_REQUEST_SIZE:
            self.send_error(413)
            return None
        return self.rfile.read(content_length)

    def send_login_redirect(self):
        self.send_response(303)
        self.send_header("Location", "/login.html")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self):
        request_path = urlsplit(self.path).path
        if request_path == "/":
            self.path = "/index.html"
            request_path = "/index.html"

        if request_path in PROTECTED_PAGES and self.current_session() is None:
            self.send_login_redirect()
            return

        if request_path == "/api/session":
            authenticated = self.current_session() is not None
            self.send_json(
                200 if authenticated else 401,
                {"authenticated": authenticated},
            )
            return

        if request_path == "/api/jobs":
            with jobs_lock:
                jobs = load_jobs()
            self.send_json(200, {"jobs": jobs})
            return

        if Path(request_path).suffix.lower() not in ALLOWED_STATIC_EXTENSIONS:
            self.send_error(404)
            return

        super().do_GET()

    def do_POST(self):
        request_path = urlsplit(self.path).path
        if request_path == "/api/login":
            self.handle_login()
        elif request_path == "/api/jobs":
            self.handle_create_job()
        else:
            self.send_error(404)

    def handle_login(self):
        if self.headers.get_content_type() != "application/x-www-form-urlencoded":
            self.send_error(415)
            return
        if not LOGIN_EMAIL or not LOGIN_PASSWORD:
            self.send_json(503, {"error": "Login service is not configured."})
            return

        body = self.read_request_body()
        if body is None:
            return
        try:
            fields = parse_qs(
                body.decode("utf-8", errors="strict"),
                keep_blank_values=True,
            )
        except UnicodeDecodeError:
            self.send_error(400, "Request body must be valid UTF-8")
            return

        emails = fields.get("email", [])
        passwords = fields.get("password", [])
        authenticated = (
            len(emails) == 1
            and len(passwords) == 1
            and hmac.compare_digest(emails[0], LOGIN_EMAIL)
            and hmac.compare_digest(passwords[0], LOGIN_PASSWORD)
        )

        if not authenticated:
            self.send_json(401, {"authenticated": False})
            return

        token = secrets.token_urlsafe(32)
        with sessions_lock:
            sessions[token] = time.time() + SESSION_TTL_SECONDS
        cookie = "apex_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}".format(
            token, SESSION_TTL_SECONDS
        )
        self.send_json(
            200,
            {"authenticated": True},
            {"Set-Cookie": cookie},
        )

    def handle_create_job(self):
        if self.current_session() is None:
            self.send_json(401, {"error": "Sign in to post a job."})
            return
        if self.headers.get_content_type() != "application/json":
            self.send_error(415)
            return

        body = self.read_request_body()
        if body is None:
            return
        try:
            fields = json.loads(body.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(400, "Request body must be valid JSON")
            return

        required = ("title", "location", "employment_type", "description")
        if not isinstance(fields, dict) or any(
            not isinstance(fields.get(name), str)
            or not fields[name].strip()
            or len(fields[name].strip()) > maximum
            for name, maximum in (
                ("title", 120),
                ("location", 120),
                ("employment_type", 80),
                ("description", 3000),
            )
        ):
            self.send_json(
                400,
                {"error": "Enter a job title, location, employment type, and description within the allowed lengths."},
            )
            return

        job = {
            "id": uuid.uuid4().hex,
            "title": fields["title"].strip(),
            "location": fields["location"].strip(),
            "employment_type": fields["employment_type"].strip(),
            "description": fields["description"].strip(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        with jobs_lock:
            jobs = load_jobs()
            jobs.insert(0, job)
            save_jobs(jobs)
        self.send_json(201, {"job": job})


def load_jobs():
    try:
        jobs = json.loads(JOBS_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("Could not read the saved job postings.") from error

    if not isinstance(jobs, list):
        raise RuntimeError("The saved job postings file has an invalid format.")
    return jobs


def save_jobs(jobs):
    JOBS_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=JOBS_FILE.parent,
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            json.dump(jobs, temporary_file, ensure_ascii=False, indent=2)
            temporary_file.write("\n")
        temporary_path.replace(JOBS_FILE)
    except OSError as error:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise RuntimeError("Could not save the job posting.") from error


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), WebsiteHandler)
    print("Serving the website at http://{}:{}".format(HOST, PORT))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping website server.")
    finally:
        server.server_close()
