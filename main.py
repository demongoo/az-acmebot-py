import asyncio
from functools import cache
from typing import Annotated, Optional
import datetime
from datetime import datetime as dt, timedelta
from secrets import compare_digest

from fastapi import Depends, FastAPI, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse

from contextlib import asynccontextmanager
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

from config import settings
from logger import logger
from renewer.renewer import CertRenewer
from service.acme import ACMEService
from service.keyvault import KeyVaultService
from service.dns import DNSService

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

# initialize dns service
if settings.dns_zone_name and settings.dns_zone_resource_group and settings.azure_subscription_id:
    dns_service = DNSService(
        credential=azure_credential,
        subscription_id=settings.azure_subscription_id,
        resource_group=settings.dns_zone_resource_group,
        zone_name=settings.dns_zone_name
    )
    logger.info(f"Initialized DNS Service for zone: {settings.dns_zone_name}")
else:
    dns_service = None
    logger.info("DNS Service not initialized (missing configuration)")

# acme factory
@cache
def acme_by_code(acme_code: str) -> Optional[ACMEService]:
    match acme_code:
        case 'letsencrypt':
            acme_server = 'https://acme-v02.api.letsencrypt.org/directory'
            acme_email = settings.acme_letsencrypt_email or settings.acme_email
        case _:
            logger.warning(f"Unknown ACME provider code: {acme_code}")
            return None

    if acme_email:
        logger.info(f'Initializing ACME provider {acme_code} with email {acme_email}')
        return ACMEService(acme_server=acme_server, acme_email=acme_email)
    else:
        logger.warning(f"ACME email not configured, cannot initialize provider {acme_code}")
        return None

def acme_factory(issuer: str) -> Optional[ACMEService]:
    if "Let's Encrypt" in issuer:
        return acme_by_code('letsencrypt')
    else:
        logger.warning(f"Unsupported issuer for ACME factory: {issuer}")
        return None

# initialize renewer processor
renewer = CertRenewer(keyvault_service, dns_service, acme_factory, settings.cert_pfx_password)
logger.info("Initialized Certificate Renewer")


# renewal locking
_renewal_lock = asyncio.Lock()

# background task
async def process_renewals():
    """
    Background task for renewals
    """
    async with _renewal_lock:
        await renewer.check_and_renew_all(settings.renewal_days_before_expiry)


# startup and shutdown events
@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info(f"Starting scheduler for {settings.process_interval} minutes, first run delay {settings.process_first_run_delay} minutes")

    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        process_renewals, "interval", coalesce=True, id="periodic_renewal_check",
        minutes=settings.process_interval,
        next_run_time=dt.now() + timedelta(minutes=settings.process_first_run_delay)
    )
    scheduler.start()

    # Store in app state
    app.state.scheduler = scheduler

    yield

    logger.info("Stopping scheduler")
    scheduler.shutdown()

    logger.info("Stopping services")
    await keyvault_service.close()
    await azure_credential.close()


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
    await dns_service.create_txt_record("test.blabla", "blablabla")

    certs_props = await keyvault_service.list_certificates()

    # Fetch full details for all certificates in parallel
    tasks = [keyvault_service.get_certificate(c.name) for c in certs_props]
    cert_bundles = await asyncio.gather(*tasks)

    certs = []
    for prop, bundle in zip(certs_props, cert_bundles):
        domain = "?"
        issuer = "? / ?"

        if bundle.cer:
            try:
                x509_cert = x509.load_der_x509_certificate(bundle.cer, default_backend())

                # Extract Subject CN
                subject_cn = x509_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if subject_cn:
                    domain = subject_cn[0].value

                # Extract Issuer CN and Organization
                issuer_cn = x509_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                issuer_cn_str = issuer_cn[0].value if issuer_cn else '?'

                issuer_org = x509_cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                issuer_org_str = issuer = issuer_org[0].value if issuer_org else '?'

                issuer = f"{issuer_cn_str}  / {issuer_org_str}"
            except Exception as e:
                logger.error(f"Error parsing cert {prop.name}: {e}")

        # status class
        if prop.expires_on:
            days_to_expiry = (prop.expires_on - dt.now(datetime.UTC)).days
            if days_to_expiry < 0:
                status_class = "expired"
            elif days_to_expiry <= settings.renewal_days_before_expiry:
                status_class = "soon"
            else:
                status_class = "valid"
        else:
            status_class = "unknown"

        certs.append({
            "name": prop.name,
            "id": prop.id,
            "domain": domain,
            "issuer": issuer,
            "expires_on": prop.expires_on.strftime("%Y-%m-%d %H:%M:%S") if prop.expires_on else "?",
            "created_on": prop.created_on.strftime("%Y-%m-%d %H:%M:%S") if prop.created_on else "?",
            "updated_on": prop.updated_on.strftime("%Y-%m-%d %H:%M:%S") if prop.updated_on else "?",
            "enabled": prop.enabled,
            "status_class": status_class
        })

    return templates.TemplateResponse("index.html", {"request": request, "certs": certs})


@app.post("/check-and-renew-all")
async def check_and_renew_all(request: Request, _: None = Depends(verify_credentials)):
    scheduler: AsyncIOScheduler = request.app.state.scheduler
    scheduler.add_job(process_renewals, id="manual_renewal_check", replace_existing=True)
    return RedirectResponse(url="/", status_code=303)