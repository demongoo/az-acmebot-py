from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from loguru import logger

from typing import Callable, Optional
from service.dns import DNSService
from service.keyvault import KeyVaultService
from service.acme import ACMEService


class CertRenewer:
    def __init__(self, keyvault_service: KeyVaultService, dns_service: DNSService,
                 acme_factory: Callable[[str], Optional[ACMEService]], pfx_password: str = None):
        self.keyvault_service = keyvault_service
        self.dns_service = dns_service
        self.acme_factory = acme_factory
        self.pfx_password = pfx_password

    async def process_certificate(self, cert_prop, renewal_days_before_expiry: int):
        logger.info(f"Processing certificate: {cert_prop.name}")

        # Fetch the certificate bundle
        cert_bundle = await self.keyvault_service.get_certificate(cert_prop.name)
        if not cert_bundle.cer:
            logger.error("No CER content, skipped")
            return

        # checking expiry
        expires_on = cert_prop.expires_on
        if not expires_on:
            logger.warning(f"No expiry date, skipped")
            return

        days_until_expiry = (expires_on - datetime.now(timezone.utc)).days
        if days_until_expiry > 0:
            logger.info(f"Expires in {days_until_expiry} days")
        else:
            logger.warning(f"Expired {abs(days_until_expiry)} days ago")

        if days_until_expiry > renewal_days_before_expiry:
            logger.info(f"No need for renewal yet, skipped")
            return

        # get issuer to determine ACME provider
        x509_cert = x509.load_der_x509_certificate(cert_bundle.cer, default_backend())
        issuer = x509_cert.issuer
        org_attributes = issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        issuer_org_name = org_attributes[0].value if org_attributes else "Unknown"
        logger.info(f"Issued by: {issuer_org_name}")

        # Determine ACME service based on issuer
        acme_service = self.acme_factory(issuer_org_name)
        if not acme_service:
            logger.warning(f"No ACME service configured for {issuer_org_name}, skipping")
            return

        # Trying to renew
        logger.info(f"Attempting certificate renewal")


    async def check_and_renew_all(self, renewal_days_before_expiry: int):
        logger.info(f"Start renewal check for all certificates, renewal threshold: {renewal_days_before_expiry} days")
        certs = await self.keyvault_service.list_certificates()
        for cert_prop in certs:
            try:
                await self.process_certificate(cert_prop, renewal_days_before_expiry)
            except Exception as e:
                logger.error(f"Error processing certificate {cert_prop.name}: {e}")


    async def renew_certificate(self, name: str, current_cert: x509.Certificate = None):
        if not current_cert:
            cert_bundle = await self.keyvault_service.get_certificate(name)
            current_cert = x509.load_der_x509_certificate(cert_bundle.cer, default_backend())
            
        san_ext = current_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
        
        print(f"Renewing for domains: {sans}")
        
        pfx_data = await acme_service.issue_certificate(sans)
        
        await keyvault_service.import_certificate(name, pfx_data, password=self.pfx_password)
        print(f"Successfully renewed and imported {name}")

