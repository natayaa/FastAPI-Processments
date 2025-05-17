import asyncio, time

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, PlainTextResponse
from collections import defaultdict, deque

from dependencies.securities import verify_csrf_token

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# need to update the middleware
# need to add another middleware
# build ddos handler middleware

class CSRFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, exempt_paths=None):
        super().__init__(app)
        self.exempt_paths = exempt_paths or []

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if path in self.exempt_paths or request.method in SAFE_METHODS or any(path.startswith(exempt) for exempt in self.exempt_paths):
            return await call_next(request)
        
        # get session id
        session_id = request.cookies.get("session_id")
        csrf_token = None

        # handle form-based
        if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            form = await request.form()
            csrf_token = form.get("csrf_token")
        # handle AJAX/JSON via custom headers
        elif request.headers.get("X-Requested-With") == "XMLHttpRequest":
            csrf_token = request.headers.get("X-CSRF-Token")

        if not session_id or not csrf_token:
            return PlainTextResponse("CSRF token or session is missing", status_code=403)
        
        if not verify_csrf_token(csrf_token, session_id):
            return PlainTextResponse("Invalid or expired CSRF Token", status_code=403)
        
        return await call_next(request)
    

class DDoSMiddleware(BaseHTTPMiddleware):
    def __init__(
        self, 
        app, 
        max_requests: int = 60, 
        window_seconds: int = 60,
        block_seconds: int = 120
    ):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window_seconds
        self.block_seconds = block_seconds

        self.requests = defaultdict(deque)         # IP: [timestamps...]
        self.blocked_ips = {}                      # IP: block_until timestamp
        self.lock = asyncio.Lock()                 # Thread safety

    async def dispatch(self, request: Request, call_next):
        ip = request.client.host
        now = time.time()

        async with self.lock:
            # Unblock expired IPs
            if ip in self.blocked_ips and now >= self.blocked_ips[ip]:
                #logger.info(f"[DDoS] Unblocking IP: {ip}")
                del self.blocked_ips[ip]

            # If blocked, reject
            if ip in self.blocked_ips:
                #logger.warning(f"[DDoS] Blocked IP attempted access: {ip}")
                return JSONResponse(
                    {"detail": "Too many requests. Try again later."},
                    status_code=429
                )

            # Track this request timestamp
            self.requests[ip].append(now)

            # Remove timestamps older than window
            while self.requests[ip] and self.requests[ip][0] < now - self.window:
                self.requests[ip].popleft()

            # Block if request count exceeds threshold
            if len(self.requests[ip]) > self.max_requests:
                self.blocked_ips[ip] = now + self.block_seconds
                #logger.warning(f"[DDoS] IP blocked: {ip} ({len(self.requests[ip])} reqs in {self.window}s)")
                return JSONResponse(
                    {"detail": "Rate limit exceeded. IP temporarily blocked."},
                    status_code=429
                )

        # Allow through
        return await call_next(request)