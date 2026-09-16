# tasky-analytics  ⚠️ SIMULATED SUPPLY-CHAIN THREAT (DEMO ONLY)

This is an intentionally malicious Go module built for the Wiz technical exercise to
demonstrate a supply-chain attack. It looks like a benign analytics helper; its `init()`
exfiltrates the importing pod's secrets (SA token, env vars incl. DB creds, IMDS role) to a
collector set via `ANALYTICS_URL`.

**Not for any real use.** Payload is env-gated and only sends to a collector you control.
