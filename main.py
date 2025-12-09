from typing import Annotated
from datetime import datetime, timedelta

from fastapi import Depends, FastAPI, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse

from contextlib import asynccontextmanager
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from config import settings
from logger import logger

from secrets import compare_digest

from service.keyvault import KeyVaultService

# initialize templates
templates = Jinja2Templates(directory="templates")

# initialize azure credential
match settings.azure_credential:
    case 'default':
        from azure.identity.aio import DefaultAzureCredential
        azure_credential = DefaultAzureCredential()
    case 'managed_identity':
        from azure.identity.aio import ManagedIdentityCredential
        azure_credential = ManagedIdentityCredential()
    case _:
        logger.error(f"Invalid azure_credential setting: {settings.azure_credential}")
        raise ValueError(f"Invalid azure_credential setting: {settings.azure_credential}")
logger.info(f"Initialized Azure Credential: {azure_credential}")

# initialize keyvault service
keyvault_service = KeyVaultService(credential=azure_credential, vault_url=settings.azure_keyvault_url)
logger.info(f"Initialized Key Vault Service for vault: {settings.azure_keyvault_url}")


# background task
async def process_renewals():
    """
    Background task for renewals
    """
    pass
    #await processor.process()


# startup and shutdown events
@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info(f"Starting scheduler for {settings.process_interval} minutes, first run delay {settings.process_first_run_delay} minutes")

    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        process_renewals, "interval", coalesce=True,
        minutes=settings.process_interval,
        next_run_time=datetime.now() + timedelta(minutes=settings.process_first_run_delay)
    )
    scheduler.start()

    yield

    logger.info("Stopping scheduler")
    scheduler.shutdown()


# FastAPI application instance
app = FastAPI(lifespan=lifespan)

security = HTTPBasic()

# Middleware to check for valid credentials
def verify_credentials(credentials: Annotated[HTTPBasicCredentials, Depends(security)]):
    correct_username = credentials and compare_digest(credentials.username, settings.username)
    correct_password = credentials and compare_digest(credentials.password, settings.password)

    if correct_username and correct_password:
        return credentials
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )


@app.get("/healthcheck")
async def healthcheck() -> dict[str, str]:
    """
    Healthcheck endpoint
    """

    return {
        'status': 'OK',
        'name': 'az-acmebot'
    }


@app.get("/", response_class=HTMLResponse)
async def root(request: Request, _: None = Depends(verify_credentials)):
    certs_props = await keyvault_service.list_certificates()
    certs = []
    for c in certs_props:
        certs.append({
            "name": c.name,
            "id": c.id,
            "expires_on": c.expires_on,
            "created_on": c.created_on,
            "updated_on": c.updated_on,
            "enabled": c.enabled,
        })

    return templates.TemplateResponse("index.html", {"request": request, "certs": certs})
