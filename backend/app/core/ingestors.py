
from abc import ABC, abstractmethod
import requests

class BaseIngestor(ABC):
    
    def __init__(self, feed_name, base_url, api_key = None):
        self.feed_name = feed_name
        self.base_url = base_url
        self.api_key = api_key

    @abstractmethod
    def fetch(self):
        pass

    @abstractmethod
    def parse(self, raw_data):
        pass

class AbuseIPIngestor(BaseIngestor):
    def __init__(self, api_key):
        super().__init__(feed_name = "AbuseIPDB", base_url="abuseipdb.com", api_key=api_key)


    def fetch(self):
        header = {
            "Accept": "application/json",
            "Key": self.api_key,
        }
        response = requests.get("https://api.abuseipdb.com/api/v2/blacklist", headers=header)

        response.raise_for_status()
        return response.json()

    def parse(self, raw_data):
        data = raw_data["data"]

        if not data:
            return []

        new_data = []

        for i in data:
            j = {
                "indicator": i["ipAddress"],
                "type":"ip",
                "source": self.feed_name,
                "severity": i["abuseConfidenceScore"],
                "country": i.get("countryCode")
            }
            new_data.append(j)
        return new_data


class AlienVaultIngestor(BaseIngestor):
    def __init__(self, api_key):
        super().__init__(feed_name = "AlienVault OTX", base_url="otx.alienvault.com", api_key=api_key)

    def fetch(self):
        header = {
            "X-OTX-API-KEY": self.api_key,
        }
        response = requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed", headers=header)

        response.raise_for_status()
        return response.json()

    def parse(self, raw_data):
        results = raw_data["results"]

        if not results:
            return []

        new_data = []
        for pulse in results:
            for entry in pulse["indicators"]:
                entries = {
                    "indicator": entry.get("indicator"),
                    "type" : entry["type"],
                    "source" : self.feed_name,
                    "severity": entry.get("severity"),
                    "country": entry.get("country")
                }
                new_data.append(entries)
        return new_data

class URLhausIngestor(BaseIngestor):

    def __init__(self):
        super().__init__(feed_name = "URLhaus", base_url="urlhaus")

    def fetch(self):
        pass

    def parse(self, raw_data):
        urls = raw_data["urls"]

        if not urls:
            return []

        new_data = []

        for url in urls:
            if url["url_status"] == "online":
                url1 = {"indicator":url['url'],
                        "type" : "url",
                        "source" : self.feed_name,
                        "severity" : url.get("threat"),
                        "country" : url.get("country")}
            else:
                continue
            new_data.append(url1)
        return new_data

class PhishTankIngestor(BaseIngestor):
    def __init__(self):
        super().__init__(feed_name = "PhishTank", base_url="phishtank")

    def fetch(self):
        pass

    def parse(self, raw_data):
        if not raw_data:
            return []

        new_data = []

        for data in raw_data:
            if data["verified"] =="yes":
                datas = {
                    "indicator":data["url"],
                    "type" : "url",
                    "source" : self.feed_name,
                    "severity" : data.get("threat"),
                    "country" : data.get("country")
                }
            else:
                continue

            new_data.append(datas)

        return new_data

class BlocklistDeIngestor(BaseIngestor):

    def __init__(self):
        super().__init__(feed_name = "Blocklist.de", base_url="blocklist.de")

    def fetch(self):
        pass

    def parse(self, raw_data):
        if not raw_data:
            return []

        new_string = raw_data.splitlines()

        new_data = []

        for line in new_string:
            line = line.strip()
            if line == "": continue
            if line.startswith("#"): continue
            data = {
                "indicator":line,
                "type" : "ip",
                "source" : self.feed_name,
                "severity" : None,
                "country" : None
            }
            new_data.append(data)

        return new_data