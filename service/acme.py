import time
import asyncio
import functools
import josepy as jose
from acme import client, messages, challenges
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import pkcs12
from app.config import settings
from app.services.dns import dns_service


async def _run_blocking(func, *args, **kwargs):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, functools.partial(func, *args, **kwargs))


class ACMEService:
    def __init__(self, acme_server: str, acme_email: str):
        self.directory_url = acme_server
        self.acme_email = acme_email
        self.user_key = jose.JWKRSA(
            key=rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
        )
        self.net = client.ClientNetwork(self.user_key, user_agent="az-acmebot-py/1.0")
        self.acme_client = client.ClientV2(self.directory_url, self.net)
        self._registered = False
        self._temp_private_key = None



    async def _ensure_registration(self):
        if not self._registered:
            def register():
                try:
                    self.acme_client.new_account(
                        messages.NewRegistration.from_data(
                            email=settings.ACME_EMAIL,
                            terms_of_service_agreed=True
                        )
                    )
                except messages.Error as e:
                    if e.code == 'urn:ietf:params:acme:error:accountDoesNotExist':
                        pass
                return True

            self._registered = await _run_blocking(register)

    async def issue_certificate(self, domains: list[str]) -> bytes:
        await self._ensure_registration()
        
        order = await _run_blocking(self.acme_client.new_order, domains)
        
        for authz in order.authorizations:
            if authz.body.status == messages.STATUS_VALID:
                continue
                
            domain = authz.body.identifier.value
            challenge = next(
                c for c in authz.body.challenges if isinstance(c.chall, challenges.DNS01)
            )
            
            response, validation = challenge.response_and_validation(self.acme_client.net.key)
            
            zone = settings.AZURE_ZONE_NAME
            if zone and domain.endswith(zone):
                relative_part = domain[:-len(zone)].strip('.')
                if relative_part:
                    record_name = f"_acme-challenge.{relative_part}"
                else:
                    record_name = "_acme-challenge"
            else:
                record_name = f"_acme-challenge.{domain}"
            
            await dns_service.create_txt_record(record_name, validation)
            
            print("Waiting for DNS propagation...")
            await asyncio.sleep(30) 
            
            await _run_blocking(self.acme_client.answer_challenge, challenge, response)
            
            # Polling
            # We can't just block here. We should poll with async sleep.
            finalized_authz = await self._poll_authz(authz)
            if finalized_authz.body.status != messages.STATUS_VALID:
                raise Exception(f"Authorization failed: {finalized_authz.body.status}")
                
            await dns_service.delete_txt_record(record_name)

        csr_pem = await _run_blocking(self._generate_csr, domains)
        order = await _run_blocking(self.acme_client.finalize_order, order, csr_pem)
        
        fullchain_pem = order.fullchain_pem.encode('utf-8')
        return await _run_blocking(self.create_pfx, fullchain_pem)

    async def _poll_authz(self, authz):
        while True:
            authz = await _run_blocking(self.acme_client.poll, authz)
            if authz.body.status in (messages.STATUS_VALID, messages.STATUS_INVALID):
                return authz
            await asyncio.sleep(2)

    def _generate_csr(self, domains: list[str]) -> bytes:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        self._temp_private_key = private_key
        
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
        ]))
        
        csr_builder = csr_builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
            critical=False,
        )
        
        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())
        return csr.public_bytes(serialization.Encoding.PEM)

    def create_pfx(self, cert_chain_pem: bytes) -> bytes:
        certs = x509.load_pem_x509_certificates(cert_chain_pem)
        leaf = certs[0]
        cas = certs[1:] if len(certs) > 1 else []
        
        if settings.PFX_PASSWORD:
            encryption = serialization.BestAvailableEncryption(settings.PFX_PASSWORD.encode())
        else:
            encryption = serialization.NoEncryption()

        pfx = pkcs12.serialize_key_and_certificates(
            name=b"acmebot",
            key=self._temp_private_key,
            cert=leaf,
            cas=cas,
            encryption_algorithm=encryption
        )
        return pfx

acme_service = ACMEService()
