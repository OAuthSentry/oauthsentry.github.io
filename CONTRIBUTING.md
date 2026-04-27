# Contributing to OAuthSentry

Thanks for helping defenders find OAuth threats faster.

## Adding a new app entry

The per-service file at `data/<service>/oauth_apps.csv` is the **build output**, not the input. To add or change an entry, file an upstream PR against `mthcht/awesome-lists` and the next workflow run picks it up. If the upstream maintainer is slow or you want a same-day fix while you wait, drop the row into `data/<service>/curated_mthcht.csv` directly and open a PR here - the next build will reflect it. Use these columns:

```
appname,appid,metadata_category,metadata_severity,metadata_comment,metadata_reference
```

Field guidance:

- **appname** - observed display name. Preserve attacker-chosen casing or homoglyphs verbatim - they are the IOC.
- **appid** - the OAuth client / application ID, lowercase UUID.
- **metadata_category** - one of `legitimate`, `risky`, `malicious` (the upstream wording - the site renames `legitimate` to `compliance` automatically). mthcht's combined categories like `Phishing - compliance` are normalized to the last token.
- **metadata_severity** - `info`, `low`, `medium`, `high`, `critical`. Reserve `critical` for confirmed in-the-wild malicious or high-impact-if-abused first-party apps.
- **metadata_comment** - analyst notes. Threat actor cluster, scopes, replyUrls, last-seen year, anything that helps another analyst triage.
- **metadata_reference** - one or more `https://...` URLs separated by ` | `. Always include at least one credible public reference for `risky` and `malicious`.

A `risky` or `malicious` entry **must** ship with at least one public reference. PRs without one will be asked for sources.

## How the data lineage works

OAuthSentry doesn't maintain its own threat-classification list; it composes two upstream sources per service and rebuilds the feeds nightly via GitHub Actions:

| Source | Role | What it provides |
|--------|------|------------------|
| [`mthcht/awesome-lists/Lists/OAuth/<service>_oauth_apps.csv`](https://github.com/mthcht/awesome-lists/tree/main/Lists/OAuth) | `curated` | The opinion. Each row carries an explicit `compliance` / `risky` / `malicious` verdict + severity + analyst comment + reference. mthcht's combined categories (e.g. `Phishing - compliance`) are split on ` - ` and the last token is taken as the canonical bucket. |
| [`merill/microsoft-info/_info/MicrosoftApps.csv`](https://github.com/merill/microsoft-info) | `compliance_fill` | The catalogue. ~600+ Microsoft first-party AppIds with display name + owner tenant. Used only as compliance fill: any AppId not already classified by the curated source is added to the compliance bucket with a `Microsoft first-party app (via merill/microsoft-info)` comment. |

**Merge precedence: curated wins on every conflict.** If mthcht has classified an AppId as `risky` (e.g. Microsoft Azure CLI - it's FOCI and has been used in BEC ops), that classification is kept even though merill lists the same AppId as a Microsoft first-party app. The fill source only adds rows whose AppIds the curated source has not seen.

The build script (`scripts/build_feeds.py`) writes the merged result to `data/<service>/oauth_apps.csv` on every run, so that file is regenerated and should not be hand-edited.

## Adding a new service

1. Identify a curated upstream source for the service (mthcht has both `entra_oauth_apps.csv` and `google_oauth_apps.csv`; Slack / GitHub / Salesforce / Okta are still planned).
2. Add a row to `data/sources.json` with `role: "curated"`:

```json
{
  "id": "google_curated_mthcht",
  "service": "google",
  "role": "curated",
  "label": "mthcht/awesome-lists - Google OAuth apps",
  "remote": "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/OAuth/google_oauth_apps.csv",
  "local":  "data/google/curated_mthcht.csv",
  "schema": "appname,appid,metadata_category,metadata_severity,metadata_comment,metadata_reference",
  "credit": "mthcht/awesome-lists",
  "credit_url": "https://github.com/mthcht/awesome-lists/tree/main/Lists/OAuth"
}
```

3. Optionally add a second row with `role: "compliance_fill"` for a vendor-published catalogue of legitimate first-party apps. The fill loader currently understands the merill schema (`AppId,AppDisplayName,AppOwnerOrganizationId,Source`); other vendor catalogues need a small adapter in `scripts/build_feeds.py` (the `load_compliance_fill` function).
4. Run `python3 scripts/build_feeds.py` locally to verify the merge counts look sane.
5. Open a PR - the site will pick up the new service automatically on next deploy.

## Removing or downgrading an entry

If an `appid` was incorrectly classified as malicious (e.g. a tenant takeover, vendor mis-attribution), open a PR with:

- the upstream report that contradicts the original classification,
- a clear analyst comment explaining the move,
- a downgrade rather than a delete where possible (e.g. `malicious` → `risky` with explanatory note), so historical hunting context is preserved.

## Code

- The site is intentionally a single static page with vanilla JS. Please do not add a build step, framework, or bundler.
- Keep the page < 200KB total (excluding data) - defenders run this from constrained networks.
- All new code paths should work with both the remote and local data fallbacks.
