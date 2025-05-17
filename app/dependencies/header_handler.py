import secrets, hashlib, time

from fastapi import status
from fastapi.security import OAuth2PasswordBearer  
from starlette.exceptions import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

class CSRFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, exempt_paths: list[str] = None):
        super().__init__(app)
        self.exempt_paths = exempt_paths or []

    def csrf_generator(self) -> str:
        randm = secrets.token_bytes(64)
        raw_tkn = f"{randm.hex()}:{int(time.time())}"
        hashed = hashlib.sha256(raw_tkn.encode("utf-8")).hexdigest()
        return hashed

    async def dispatch(self, request: Request, call_next):
        path = str(request.url.path)
        if path in self.exempt_paths:
            return await call_next(request)
        
        # for safe methods (GET, HEAD, OPTIONS)
        if request.method in ("GET", "HEAD", "OPTIONS"):
            token = request.cookies.get("") # Should i put it into config for http header security ?
            if not token:
                token = self.csrf_generator()
                response = await call_next(request)
                response.set_cookie(key="", value=token, httponly=False, samesite="lax", secure=False, path="/")

                return response
            else:
                return await call_next(request)
            
        csrf_cookie = request.cookies.get("")
        csrf_header = request.headers.get("")

        if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
            return HTTPException(headers={"error": "CSRF Token is missing or invalid"}, status_code=status.HTTP_406_NOT_ACCEPTABLE, detail={"error": "CSRF Token is missing or invalid"})
        
        return await call_next(request)
    

class CustomSecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        response.headers['Strict-Transport-Security'] = f""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1;mode=block"
        response.headers["X-Frame-Options"] = "ALLOW"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["geolocation=()"]

        csp = (
            "default-src 'self';"
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'self';"
        )

        response.headers["Content-Security-Policy"] = csp
        return response
    

class SecureOAuth2Bearer(OAuth2PasswordBearer):
    def __init__(self, tokenUrl: str = "", auto_err: bool = True):
        super().__init__(tokenUrl=tokenUrl, auto_error=auto_err)

    async def __call__(self, request: Request) -> str:
        auth = request.headers.get("Authorization")
        if not auth or not auth.lower().startswith("bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token or missing the token itself", headers={"WWW-Authenticate": "Bearer"})
        
        return await super().__call__(request)
    