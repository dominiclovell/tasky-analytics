⚠️ SIMULATED SUPPLY-CHAIN THREAT

This is an intentionally malicious Go module built for the Wiz technical exercise to
demonstrate a supply-chain attack. It looks like a benign analytics helper; its `init()`
exfiltrates the importing pod's secrets (SA token, env vars incl. DB creds, IMDS role) to a
collector set via `ANALYTICS_URL`.
