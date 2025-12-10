from azure.mgmt.dns.aio import DnsManagementClient

class DNSService:
    def __init__(self, credential, subscription_id: str, resource_group: str, zone_name: str):
        self.credential = credential
        self.zone_name = zone_name
        self.resource_group = resource_group
        self.client = DnsManagementClient(self.credential, subscription_id)

    async def create_txt_record(self, record_name: str, record_value: str):
        params = {
            "ttl": 60,
            "txt_records": [{"value": [record_value]}]
        }
        
        await self.client.record_sets.create_or_update(
            self.resource_group,
            self.zone_name,
            record_name,
            "TXT",
            params
        )

    async def delete_txt_record(self, record_name: str):
        try:
            await self.client.record_sets.delete(
                self.resource_group,
                self.zone_name,
                record_name,
                "TXT"
            )
        except Exception as e:
            pass
            
    async def close(self):
        await self.client.close()
