# OAuthSentry

> OAuth application intelligence for defense teams.
> Hosted at **[oauthsentry.github.io](https://oauthsentry.github.io)**.

OAuthSentry is a static, search-first inventory of OAuth Application IDs across identity platforms (Microsoft Entra to start, with Google Workspace, Slack, GitHub, Salesforce and Okta planned). Every app is bucketed into one of three defender-oriented categories:

| Category       | Meaning |
|----------------|---------|
| **Compliance** | Legitimate first-party or vetted third-party apps. Reference data for allowlists and hunt-tuning. |
| **Risky**      | Legitimate apps that are repeatedly seen in attacker tradecraft - mailbox sync clients, cloud-storage sync tools, first-party apps abused via AADInternals/EvilProxy. |
| **Malicious**  | Confirmed in-the-wild malicious apps: consent phishing, AiTM lures, homoglyph impersonations, threat-actor redirect apps. |

The site is a single static page (no backend, no build step) that fetches the upstream community-curated CSV at load time and falls back to a snapshot mirrored in this repo. Every list is also exported as plain-text and CSV feeds under `feeds/` for direct ingestion into a SIEM/EDR.

---

## Repository layout

```
oauthsentry.github.io/
├── index.html                          single-page search UI
├── assets/
│   ├── css/style.css
│   └── js/app.js                       vanilla JS, no framework
├── data/
│   ├── sources.json                    registry: per-service curated + compliance_fill sources
│   ├── entra/
│   │   ├── curated_mthcht.csv          mirrored from mthcht/awesome-lists (the opinion)
│   │   ├── compliance_fill_merill.csv  mirrored from merill/microsoft-info (the catalogue)
│   │   └── oauth_apps.csv              merged source-of-truth (rebuilt every run)
│   └── google/curated_mthcht.csv       mirrored from mthcht/awesome-lists
├── feeds/                              auto-generated outputs
│   ├── entra/{compliance,risky,malicious}.{txt,csv}
│   ├── entra/all.json
│   ├── google/{compliance,risky,malicious}.{txt,csv}
│   ├── all/{compliance,risky,malicious}.{txt,csv}
│   ├── all/index.json
│   └── summary.json
├── scripts/build_feeds.py              merges curated + compliance_fill, regenerates feeds/
└── .github/workflows/update.yml        pulls every source daily and rebuilds
```

---

## Feed URLs

Once published at `https://oauthsentry.github.io`, the following stable URLs are available:

### Per-service (Entra)

```
https://oauthsentry.github.io/feeds/entra/compliance.txt
https://oauthsentry.github.io/feeds/entra/compliance.csv
https://oauthsentry.github.io/feeds/entra/risky.txt
https://oauthsentry.github.io/feeds/entra/risky.csv
https://oauthsentry.github.io/feeds/entra/malicious.txt
https://oauthsentry.github.io/feeds/entra/malicious.csv
https://oauthsentry.github.io/feeds/entra/all.json
```

### Combined across all services

```
https://oauthsentry.github.io/feeds/all/compliance.txt
https://oauthsentry.github.io/feeds/all/risky.txt
https://oauthsentry.github.io/feeds/all/malicious.txt
https://oauthsentry.github.io/feeds/all/index.json
https://oauthsentry.github.io/feeds/summary.json
```

`.txt` feeds are one App ID per line with `#` headers - drop straight into a SIEM lookup or a watchlist.

### Example uses

```bash
# Pull the malicious feed directly into a Splunk lookup
curl -s https://oauthsentry.github.io/feeds/all/malicious.txt | grep -v '^#' > malicious_oauth_apps.csv
```

```kql
// Sentinel/Defender - flag OAuth consent grants for known-malicious app IDs
let malicious = externaldata(appid:string)[
  "https://oauthsentry.github.io/feeds/all/malicious.txt"
] with (format="txt");
AuditLogs
| where OperationName == "Consent to application"
| extend appid = tostring(parse_json(TargetResources)[0].id)
| where appid in (malicious | project appid)
```

---

## Categories - ground rules

OAuthSentry uses category labels different from the upstream CSV. The mapping is fixed in code:

| Upstream label | OAuthSentry label |
|----------------|-------------------|
| `legitimate`   | `compliance` |
| `risky`        | `risky` |
| `malicious`    | `malicious` |

`severity` is preserved from upstream (`info`, `low`, `medium`, `high`, `critical`) and shown alongside the category.

---

## Data sources

Each service composes one or more upstream sources, declared in [`data/sources.json`](data/sources.json) with a `role` field:

| Role | What it does |
|------|--------------|
| `curated` | The opinion list. Each row carries an explicit category, severity, comment and reference. mthcht's `awesome-lists` is the curated source for both Entra and Google today. |
| `compliance_fill` | Catalogue-style first-party app inventory. Every row that the curated source has not already classified is added to compliance, with metadata indicating its provenance. merill's `microsoft-info` plays this role for Entra. |
| `planned` | Service is on the roadmap but no upstream source is wired up yet. |

**Curated wins on every conflict.** If mthcht classifies an AppId as `risky` (e.g. Microsoft Azure CLI - it's part of the FOCI family and abused in token-theft chains), that classification holds even though merill lists the same AppId as a Microsoft first-party app. Fill rows only fill gaps.

Currently active:

- **Microsoft Entra** - curated by [`mthcht/awesome-lists`](https://github.com/mthcht/awesome-lists/tree/main/Lists/OAuth), compliance-filled from [`merill/microsoft-info`](https://github.com/merill/microsoft-info) (~600+ Microsoft first-party AppIds).
- **Google Workspace** - curated by [`mthcht/awesome-lists`](https://github.com/mthcht/awesome-lists/tree/main/Lists/OAuth).

Planned: Slack, GitHub, Salesforce, Okta. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Updating the data

The [`update.yml`](.github/workflows/update.yml) workflow runs daily at 04:17 UTC:

1. Iterates every source in `data/sources.json` whose `role` is `curated` or `compliance_fill`.
2. Pulls each `remote` URL and writes the body to its `local` path. Logs which sources changed, which were unchanged, and which failed.
3. Runs `python3 scripts/build_feeds.py`, which:
   - Loads each curated source as the source of truth (mthcht's combined categories like `Phishing - compliance` are normalized to the last token).
   - Loads each compliance_fill source and inserts only AppIds the curated source has not classified, defaulting them to `compliance` / `info` with a `Microsoft first-party app (via merill/microsoft-info)` comment.
   - Writes the merged result to `data/<service>/oauth_apps.csv` and regenerates everything under `feeds/`.
4. Commits any diff back to `main` with `[skip ci]` to avoid loops.

Run it locally:

```bash
python3 scripts/build_feeds.py
```

---

## Hosting on `oauthsentry.github.io`

This repo is structured as a GitHub user/organization site:

1. Create the GitHub organization or user `oauthsentry`.
2. Create a public repo named **exactly** `oauthsentry.github.io`.
3. Push this repo's contents to `main`.
4. In repository **Settings → Pages**, set the source to **`main` / root**.
5. The site is live at `https://oauthsentry.github.io` within a minute or two.

---

## Acknowledgements

OAuthSentry is a thin, defender-oriented frontend over work done by:

- [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists) - the primary Entra dataset
- [randomaccess3/detections](https://github.com/randomaccess3/detections)
- [Cyera-Research-Labs/m365-malicious-app-iocs](https://github.com/Cyera-Research-Labs/m365-malicious-app-iocs)
- [anak0ndah/EntraHunt](https://github.com/anak0ndah/EntraHunt)
- [merill/microsoft-info](https://github.com/merill/microsoft-info)
- Wiz, Proofpoint/RH-ISAC, Huntress, ByteIntoCyber and many others for individual reports.

Defenders, not vendors. PRs welcome.

## License

MIT for the code in this repo. The mirrored data preserves the upstream license/terms of each source.
