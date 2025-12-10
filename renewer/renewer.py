from datetime import datetime, timezone, timedelta
from app.services.keyvault import keyvault_service
from app.services.acme import acme_service
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from app.config import settings

from loguru import logger

from typing import Callable, Optional
from service.dns import DNSService
from service.keyvault import KeyVaultService
from service.acme import ACMEService


class CertRenewer:
    def __init__(self, keyvault_service: KeyVaultService, dns_service: DNSService, acme_factory: Callable[[str], Optional[ACMEService]]):
        self.keyvault_service = keyvault_service
        self.dns_service = dns_service
        self.acme_factory = acme_factory

    async def process_certificate(self, cert_prop, renewal_days_before_expiry: int):
        logger.info(f"Processing certificate: {cert_prop.name}")

        # Fetch the certificate bundle
        cert_bundle = await keyvault_service.get_certificate(cert_prop.name)
        if not cert_bundle.cer:
            logger.error(f"Certificate {cert_prop.name} has no CER content")
            return

        x509_cert = x509.load_der_x509_certificate(cert_bundle.cer, default_backend())
        issuer = x509_cert.issuer.rfc4514_string()

        if "Let's Encrypt" not in issuer:
            print(f"Skipping {cert_prop.name}: Issuer is {issuer}")
            return

        expires_on = cert_prop.expires_on
        if not expires_on:
            print(f"Skipping {cert_prop.name}: No expiry date.")
            return

        days_until_expiry = (expires_on - datetime.now(timezone.utc)).days
        print(f"Certificate {cert_prop.name} expires in {days_until_expiry} days.")

        if days_until_expiry < 30:
            print(f"Renewing {cert_prop.name}...")
            await self.renew_certificate(cert_prop.name, x509_cert)
        else:
            print(f"Certificate {cert_prop.name} is still valid.")

    async def check_and_renew_all(self):
        print("Starting renewal check...")
        certs = await keyvault_service.list_certificates()
        for cert_prop in certs:
            try:
                await self.process_certificate(cert_prop)
            except Exception as e:
                print(f"Error processing certificate {cert_prop.name}: {e}")
        print("Renewal check completed.")



    async def renew_certificate(self, name: str, current_cert: x509.Certificate = None):
        if not current_cert:
            cert_bundle = await keyvault_service.get_certificate(name)
            current_cert = x509.load_der_x509_certificate(cert_bundle.cer, default_backend())
            
        san_ext = current_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
        
        print(f"Renewing for domains: {sans}")
        
        pfx_data = await acme_service.issue_certificate(sans)
        
        await keyvault_service.import_certificate(name, pfx_data, password=settings.PFX_PASSWORD)
        print(f"Successfully renewed and imported {name}")

