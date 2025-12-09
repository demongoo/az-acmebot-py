from azure.keyvault.certificates.aio import CertificateClient

class KeyVaultService:
    def __init__(self, credential, vault_url: str):
        self.credential = credential
        self.client = CertificateClient(vault_url=vault_url, credential=self.credential)

    async def list_certificates(self) -> list:
        """List all certificates in the Key Vault."""
        return [cert async for cert in self.client.list_properties_of_certificates()]

    async def get_certificate(self, name: str):
        """Get a specific certificate details."""
        return await self.client.get_certificate(name)

    async def import_certificate(self, name: str, pfx_data: bytes, password: str = None):
        """Import a renewed certificate."""
        return await self.client.import_certificate(certificate_name=name, certificate_data=pfx_data, password=password)
    
    async def close(self):
        await self.client.close()
