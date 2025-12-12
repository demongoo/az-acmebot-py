from datetime import datetime, timezone, timedelta

from azure.keyvault.certificates import CertificateProperties, KeyVaultCertificate
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
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

    async def process_certificate(self, cert_prop, renewal_days_before_expiry: int, cert_bundle: Optional[KeyVaultCertificate] = None):
        logger.info(f"Processing certificate: {cert_prop.name}")

        # Fetch the certificate bundle
        if cert_bundle is None:
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
        await self.renew_certificate(cert_prop, x509_cert, acme_service)


    async def check_and_renew_all(self, renewal_days_before_expiry: int):
        logger.info(f"Start renewal check for all certificates, renewal threshold: {renewal_days_before_expiry} days")
        certs = await self.keyvault_service.list_certificates()
        for cert_prop in certs:
            try:
                await self.process_certificate(cert_prop, renewal_days_before_expiry)
            except Exception as e:
                # log exception with stack trace
                logger.error(f"Error processing certificate {cert_prop.name}: {e}")

    async def renew_by_name(self, cert_name: str, renewal_days_before_expiry: int):
        logger.info(f"Start renewal for certificate: {cert_name}")
        cert = await self.keyvault_service.get_certificate(cert_name)
        if not cert:
            logger.error(f"Certificate {cert_name} not found in Key Vault")
            return

        await self.process_certificate(cert.properties, renewal_days_before_expiry, cert_bundle=cert)

    async def renew_certificate(self, cert_prop: CertificateProperties, current_cert: x509.Certificate, acme_service: ACMEService):
        logger.info(f'Renewing certificate: {cert_prop.name}')

        # extracting domains from current cert
        san_ext = current_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
        logger.info(f"Domains: {sans}")

        async def add_validation_record(domain: str, validation: str) -> bool:
            if not self.dns_service:
                logger.error("No DNS service configured for DNS-01 challenge")
                return False

            zone = self.dns_service.zone_name
            if domain.endswith(zone):
                relative_part = domain[:-len(zone)].strip('.')
                if relative_part:
                    record_name = f"_acme-challenge.{relative_part}"
                else:
                    record_name = "_acme-challenge"
            else:
                record_name = f"_acme-challenge.{domain}"

            logger.info(f"Creating TXT record {record_name} with value {validation}")
            await self.dns_service.create_txt_record(record_name, validation)
            return True
        
        full_chain_pem, private_key = await acme_service.issue_certificate(sans, add_validation_record)

        # creating pfx
        logger.info('Creating PFX package')
        pfx_data = self.create_pfx(cert_prop.name, full_chain_pem, private_key, self.pfx_password)

        # importing to Key Vault
        logger.info('Importing renewed certificate to Key Vault')
        await self.keyvault_service.import_certificate(cert_prop.name, pfx_data, password=self.pfx_password)

    def create_pfx(self, name: str, full_chain_pem: bytes, private_key: RSAPrivateKey, password: str = None) -> bytes:
        certs = x509.load_pem_x509_certificates(full_chain_pem)
        leaf = certs[0]
        cas = certs[1:] if len(certs) > 1 else []

        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption = serialization.NoEncryption()

        data = pkcs12.serialize_key_and_certificates(
            name=name.encode('utf-8'),
            key=private_key,
            cert=leaf,
            cas=cas,
            encryption_algorithm=encryption
        )
        return data


