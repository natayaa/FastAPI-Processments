import uvicorn, logging

from fastapi import FastAPI, Request
from fastapi.responses import Response, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware import Middleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware
from datetime import datetime

from dependencies.config import GatewayConfig
from dependencies.middlewares import CSRFMiddleware, DDoSMiddleware

host_config = GatewayConfig()
logger = logging.getLogger("uvicorn")
origins_list = ["*"]
ACCEPTED_METHODS = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH"]
ALLOWED_HEADERS = ["*"] # fill the list if you want
EXPOSED_HEADERS = ["Authorization", "Content-Type", "XMLHttpRequest"]
middlewares = [
    Middleware(CSRFMiddleware, exempt_paths=["/api/public"]),
    #Middleware(HTTPSRedirectMiddleware),
    Middleware(GZipMiddleware, minimum_size=1000),
    Middleware(SessionMiddleware, secret_key=host_config.API_SECRETKEY),
    Middleware(DDoSMiddleware),
    Middleware(CORSMiddleware,
               allow_origins=origins_list,
               allow_credentials=True,
               allow_methods=ACCEPTED_METHODS,
               allow_headers=ALLOWED_HEADERS,
               expose_headers=EXPOSED_HEADERS,
            )
]

console = FastAPI(
    title=str(host_config.API_NAME), 
    docs_url="/docs" if host_config.API_ENABLE_DOCS else None,
    middleware=middlewares
)

# middleware http header
@console.middleware("http")
async def log_sec_headers(request: Request, call_next):
    response = await call_next(request)
    sec_headers = ["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", 
                   "X-Frame-Options"]
    miss = [h for h in sec_headers if not h in response.headers]
    if miss:
        logger.warning(f"{datetime.now()} is missing : {miss}")

    return response


@console.get("/", response_class=JSONResponse)
async def hoome(request: Request):
    import uuid
    from dependencies.securities import csrf_token_generator
    session_id = request.cookies.get("session_id")
    if not session_id:
        session_id = str(uuid.uuid4())

    csrf_token = await csrf_token_generator(session_id=session_id)

    respon = JSONResponse(content="OK")
    respon.set_cookie("session_id", session_id)
    respon.set_cookie("csrf_token", csrf_token)
    return respon

if __name__ == "__main__":
    uvicorn.run(
        app="main:console", 
        host=host_config.APP_HOST, 
        port=host_config.APP_PORT, 
        reload=host_config.APP_DEBUG
    )