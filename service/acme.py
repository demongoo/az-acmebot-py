from datetime import datetime, timedelta
import asyncio
import functools
import josepy as jose
from acme import client, messages, challenges
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import CertificateSigningRequest
from cryptography.x509.oid import NameOID
from typing import Callable, TypeVar, ParamSpec, Awaitable
from loguru import logger


P = ParamSpec('P')
R = TypeVar('R')

async def _run_blocking(func: Callable[P, R], /,  *args: P.args, **kwargs: P.kwargs) -> R:
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
        self.directory = client.ClientV2.get_directory(self.directory_url, self.net)
        self.acme_client = client.ClientV2(self.directory, self.net)
        self.__registered = False

    async def __ensure_registration(self):
        if not self.__registered:
            def register():
                try:
                    self.acme_client.new_account(
                        messages.NewRegistration.from_data(
                            email=self.acme_email,
                            terms_of_service_agreed=True
                        )
                    )
                except messages.Error as e:
                    if e.code == 'urn:ietf:params:acme:error:accountDoesNotExist':
                        pass

                return True

            self.__registered = await _run_blocking(register)

    async def issue_certificate(self, domains: list[str], dns_add_validation: Callable[[str, str], Awaitable[bool]]) -> tuple[bytes, RSAPrivateKey]:
        logger.info(f'Issuing certificate for domains: {domains}')

        logger.info("Ensuring registration with ACME server")
        await self.__ensure_registration()

        pk, csr = await _run_blocking(self.__generate_csr, domains)
        logger.info(f'Generated CSR: CN={csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}')

        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        order = await _run_blocking(self.acme_client.new_order, csr_pem)
        logger.info(f'New order created')

        for authz in order.authorizations:
            if authz.body.status == messages.STATUS_VALID:
                continue

            domain = authz.body.identifier.value
            challenge = next(
                c for c in authz.body.challenges if isinstance(c.chall, challenges.DNS01)
            )

            response, validation = challenge.response_and_validation(self.acme_client.net.key)

            logger.info(f"Performing DNS-01 challenge for domain: {domain}, validation: {validation}")
            validated = await dns_add_validation(domain, validation)
            if not validated:
                raise Exception(f"DNS validation failed for domain: {domain}")

            logger.info("Waiting for DNS propagation")
            await asyncio.sleep(30)

            await _run_blocking(self.acme_client.answer_challenge, challenge, response)

            # Polling for authorization status
            async def poll_authz(authz):
                wait_time = 120
                poll_interval = 5
                while wait_time > 0:
                    authz, rsp = await _run_blocking(self.acme_client.poll, authz)
                    if authz.body.status in (messages.STATUS_VALID, messages.STATUS_INVALID):
                        return authz
                    await asyncio.sleep(poll_interval)
                    wait_time -= poll_interval

                raise Exception('Authz polling timed out')

            finalized_authz = await poll_authz(authz)
            if finalized_authz.body.status != messages.STATUS_VALID:
                raise Exception(f"Authorization failed: {finalized_authz.body.status}")

        logger.info("Finalizing order and obtaining certificate")
        deadline = datetime.now() + timedelta(seconds=90)
        order = await _run_blocking(self.acme_client.finalize_order, order, deadline)

        return order.fullchain_pem.encode('utf-8'), pk

    def __generate_csr(self, domains: list[str]) -> tuple[RSAPrivateKey, CertificateSigningRequest]:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
        ]))
        
        csr_builder = csr_builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
            critical=False
        )
        
        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())
        return private_key, csr
