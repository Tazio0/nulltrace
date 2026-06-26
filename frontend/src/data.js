export const navItems = [
  { id: "signal", label: "Globe" },
  { id: "monitor", label: "Monitor" },
  { id: "feed", label: "Feed" },
  { id: "discord", label: "Discord" },
  { id: "exports", label: "Exports" },
  { id: "system", label: "System" }
];

export const routeColors = {
  critical: "#d84b4b",
  high: "#b98662",
  medium: "#d7c48c",
  low: "#f3f3ee"
};

export const routes = [
  {
    id: "lagos-jhb",
    origin: "Lagos, NG",
    originCode: "NG",
    originLat: 6.5244,
    originLon: 3.3792,
    target: "Johannesburg, ZA",
    targetCode: "ZA",
    targetLat: -26.2041,
    targetLon: 28.0473,
    severity: "critical",
    source: "AbuseIPDB",
    vector: "credential spray",
    count: 97,
    confidence: 94
  },
  {
    id: "singapore-cape-town",
    origin: "Singapore, SG",
    originCode: "SG",
    originLat: 1.3521,
    originLon: 103.8198,
    target: "Cape Town, ZA",
    targetCode: "ZA",
    targetLat: -33.9249,
    targetLon: 18.4241,
    severity: "high",
    source: "URLhaus",
    vector: "phishing URL",
    count: 44,
    confidence: 88
  },
  {
    id: "moscow-london",
    origin: "Moscow, RU",
    originCode: "RU",
    originLat: 55.7558,
    originLon: 37.6173,
    target: "London, UK",
    targetCode: "GB",
    targetLat: 51.5072,
    targetLon: -0.1276,
    severity: "medium",
    source: "AlienVault OTX",
    vector: "scanner cluster",
    count: 31,
    confidence: 76
  },
  {
    id: "sao-paulo-frankfurt",
    origin: "Sao Paulo, BR",
    originCode: "BR",
    originLat: -23.5558,
    originLon: -46.6396,
    target: "Frankfurt, DE",
    targetCode: "DE",
    targetLat: 50.1109,
    targetLon: 8.6821,
    severity: "high",
    source: "PhishTank",
    vector: "credential lure",
    count: 63,
    confidence: 90
  },
  {
    id: "virginia-durban",
    origin: "Ashburn, US",
    originCode: "US",
    originLat: 39.0438,
    originLon: -77.4874,
    target: "Durban, ZA",
    targetCode: "ZA",
    targetLat: -29.8587,
    targetLon: 31.0218,
    severity: "critical",
    source: "Blocklist.de",
    vector: "ssh brute force",
    count: 112,
    confidence: 96
  },
  {
    id: "tokyo-sydney",
    origin: "Tokyo, JP",
    originCode: "JP",
    originLat: 35.6762,
    originLon: 139.6503,
    target: "Sydney, AU",
    targetCode: "AU",
    targetLat: -33.8688,
    targetLon: 151.2093,
    severity: "low",
    source: "Spiderweb",
    vector: "honeypot probe",
    count: 18,
    confidence: 62
  }
].map((route, index) => ({
  ...route,
  color: routeColors[route.severity],
  speed: 0.055 + index * 0.006,
  offset: index * 0.17
}));

export const metrics = [
  { label: "Signals observed", value: "1,284", detail: "mock live window" },
  { label: "Critical", value: "37", detail: "review first" },
  { label: "ZA routes", value: "3", detail: "landing focus" },
  { label: "Export-ready", value: "89", detail: "manual action" }
];

export const feedItems = [
  {
    indicator: "185.220.101.42",
    source: "AbuseIPDB",
    severity: "critical",
    type: "IP address",
    context: "Repeated reports across public feeds. Candidate for reviewed blocklist export.",
    meta: ["ZA watch", "94% confidence", "ssh abuse"]
  },
  {
    indicator: "malicious-login-check[.]xyz",
    source: "URLhaus",
    severity: "high",
    type: "Domain",
    context: "Credential harvesting pattern seen in the demo stream.",
    meta: ["phishing", "88% confidence", "alert preview"]
  },
  {
    indicator: "91.240.118.172",
    source: "AlienVault OTX",
    severity: "medium",
    type: "IP address",
    context: "Moderate confidence. Useful for analyst context, not automatic blocking.",
    meta: ["external report", "76% confidence", "needs review"]
  }
];

export const pipeline = [
  "Ingest",
  "Normalize",
  "De-duplicate",
  "Score",
  "Notify",
  "Export"
];

export const futureEndpoints = [
  "/api/threats/live",
  "/api/threats/stats",
  "/api/map/heatmap-data",
  "/api/sa/threats",
  "/api/sa/stats"
];
