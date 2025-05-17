from fastapi import APIRouter, status, Request, HTTPException, Depends

from dependencies.config import GatewayConfig

cnf = GatewayConfig()
endpoints = APIRouter(prefix=cnf.API_DEFAULT_ADDRESS_PATH, tags=["Endpoints"])
