#!/usr/bin/env python3
"""
Refreshes the JSON reference files used by the token decoder
(/#/tokens) from authoritative upstream sources.

Outputs (assets/data/):
  entra_role_wids.json           - Microsoft Entra built-in roles + template IDs
  entra_known_apps.json          - FOCI list + adjacent first-party Microsoft apps
  entra_claims_reference.json    - hand-curated claims reference (no upstream fetch)
  entra_high_risk_scopes.json    - hand-curated scope risk tiers (no upstream fetch)

Sources fetched live:
  - https://raw.githubusercontent.com/MicrosoftDocs/entra-docs/main/docs/identity/role-based-access-control/permissions-reference.md
  - https://raw.githubusercontent.com/secureworks/family-of-client-ids-research/main/known-foci-clients.csv

Hand-curated files are preserved if they exist; only re-emitted by hand-edit.
This script never wipes them.
"""

import json
import re
import sys
import urllib.request
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
DATA = REPO / 'assets' / 'data'
DATA.mkdir(parents=True, exist_ok=True)

USER_AGENT = 'OAuthSentry-DecoderRefresh/1.0'


def http_get(url, timeout=60):
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode('utf-8', errors='replace')


# -----------------------------------------------------------------------------
# Microsoft Entra built-in roles -> wids decoder
# -----------------------------------------------------------------------------

PERMISSIONS_REF_URL = (
    'https://raw.githubusercontent.com/MicrosoftDocs/entra-docs/main/'
    'docs/identity/role-based-access-control/permissions-reference.md'
)

# The "All roles" table in permissions-reference.md uses this row format:
#   | [Role Name](#anchor) | Description text. [Privileged label icon.](url) | template-id-guid |
# We pick rows out by matching the GUID at the end and extracting the bracketed name.
ROLE_ROW_RE = re.compile(
    r'\|\s*\[([^\]]+?)\]\([^)]*\)\s*\|\s*(.*?)\s*\|\s*'
    r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})'
    r'\s*\|',
    re.MULTILINE,
)
PRIV_HINT_RE = re.compile(r'Privileged label icon\.', re.IGNORECASE)


def build_wids_json():
    print('Fetching Microsoft Entra built-in roles from MicrosoftDocs/entra-docs...')
    md = http_get(PERMISSIONS_REF_URL)
    roles = {}
    for m in ROLE_ROW_RE.finditer(md):
        name = m.group(1).strip()
        desc_raw = m.group(2).strip()
        guid = m.group(3).lower()
        privileged = bool(PRIV_HINT_RE.search(desc_raw))
        # Strip the "[Privileged label icon.](...)" markdown out of the description
        desc = re.sub(r'\[Privileged label icon\.\]\([^)]*\)', '', desc_raw).strip()
        # Strip any trailing markdown image / HTML noise
        desc = re.sub(r'\s+', ' ', desc).strip()
        roles[guid] = {
            'name': name,
            'description': desc,
            'privileged': privileged,
        }

    # The synthetic default-user wid present on every non-guest tenant member
    # (this is not in the built-in roles list because it is not a real role)
    roles['b79fbf4d-3ef9-4689-8143-76b194e85509'] = {
        'name': 'Default user (no admin role)',
        'description': (
            "Synthetic wid present on every non-guest tenant member's token. "
            'Indicates the user holds no Microsoft Entra admin role - regular tenant '
            'user only. Not a real built-in role; not assignable.'
        ),
        'privileged': False,
        'synthetic': True,
    }

    out = DATA / 'entra_role_wids.json'
    out.write_text(json.dumps(roles, indent=2, sort_keys=True))
    priv = sum(1 for v in roles.values() if v.get('privileged'))
    print(f'  -> {out} ({len(roles)} roles, {priv} privileged, {out.stat().st_size:,} bytes)')


# -----------------------------------------------------------------------------
# FOCI client list (Secureworks) + adjacent first-party Microsoft apps
# -----------------------------------------------------------------------------

FOCI_CSV_URL = (
    'https://raw.githubusercontent.com/secureworks/'
    'family-of-client-ids-research/main/known-foci-clients.csv'
)

# Adjacent first-party app ids that are NOT on the FOCI list but are
# routinely seen in audit logs and worth annotating. Hand-maintained.
ADJACENT_APPS = {
    '29d9ed98-a469-4536-ade2-f981bc1d605e': {
        'name': 'Microsoft Authentication Broker',
        'publisher': 'Microsoft', 'foci': False,
        'notes': "NOT on Secureworks' canonical FOCI list, but the standard Windows client for Entra device-join and Primary Refresh Token (PRT) issuance. Favourite vector for PRT phishing per Dirk-jan Mollema's research; UTA0355 and Storm-2372 both used MAB.",
    },
    '1b730954-1685-4b74-9bfd-dac224a7b894': {
        'name': 'Azure Active Directory PowerShell',
        'publisher': 'Microsoft', 'foci': False,
        'notes': 'Legacy AzureAD module client id. Also used by AADInternals tooling. Abused in Storm-2372 device-code waves.',
    },
    'fb78d390-0c51-40cd-8e17-fdbfab77341b': {
        'name': 'Microsoft Exchange REST API Based PowerShell',
        'publisher': 'Microsoft', 'foci': False,
        'notes': 'Exchange Online PowerShell V2/V3 module client. Common in admin operations; also abused in token-theft scenarios.',
    },
    '9bc3ab49-b65d-410a-85ad-de819febfddc': {
        'name': 'SharePoint Online Management Shell',
        'publisher': 'Microsoft', 'foci': False,
        'notes': 'SPO PnP / Management Shell client. Abused by AADInternals tooling.',
    },
    '00000003-0000-0000-c000-000000000000': {
        'name': 'Microsoft Graph',
        'publisher': 'Microsoft', 'foci': False,
        'notes': 'The Microsoft Graph API itself - typically appears as the audience (aud) of access tokens, not the client. Seeing this as appid is rare and worth investigating.',
    },
    '00000002-0000-0000-c000-000000000000': {
        'name': 'Microsoft Azure AD Graph (legacy)',
        'publisher': 'Microsoft', 'foci': False,
        'notes': 'The Azure AD Graph API (graph.windows.net) - legacy, deprecated in favor of Microsoft Graph. Appearing as a token audience implies use of legacy AAD Graph code paths.',
    },
    '00000003-0000-0ff1-ce00-000000000000': {
        'name': 'Office 365 SharePoint Online',
        'publisher': 'Microsoft', 'foci': False,
        'notes': 'SharePoint Online resource. Common audience on tokens scoped to SharePoint.',
    },
    '00000002-0000-0ff1-ce00-000000000000': {
        'name': 'Office 365 Exchange Online',
        'publisher': 'Microsoft', 'foci': False,
        'notes': 'Exchange Online resource. Common audience on tokens scoped to Exchange/EWS.',
    },
    'fdd7719f-d61e-4592-b501-793734eb8a0e': {
        'name': 'Azure VPN client',
        'publisher': 'Microsoft', 'foci': False,
        'notes': 'Azure VPN client id; appears in some Storm-2372 IOC sets.',
    },
    '04f0c124-f2bc-4f59-8241-bf6df9866bbd': {
        'name': 'Visual Studio (modern)',
        'publisher': 'Microsoft', 'foci': False,
        'notes': 'First-party modern Visual Studio app id. Observed in Storm-2372 / APT29 device-code phishing waves (2025).',
    },
    'aebc6443-996d-45c2-90f0-388ff96faa56': {
        'name': 'Visual Studio Code',
        'publisher': 'Microsoft', 'foci': False,
        'notes': 'First-party VS Code app abused by Volexity-tracked UTA0352 cluster in 2025 OAuth phishing campaign against Ukraine-related NGOs.',
    },
    '1aec7268-9e30-4bf6-9a17-3c64ef91c12b': {
        'name': 'PowerApps Web',
        'publisher': 'Microsoft', 'foci': False,
        'notes': 'Microsoft Power Apps web client.',
    },
}


def build_known_apps_json():
    print('Fetching Secureworks FOCI list...')
    csv = http_get(FOCI_CSV_URL)
    apps = {}

    # Parse the CSV - schema is: client_id,name (sometimes with quotes/whitespace)
    import csv as csv_lib
    import io
    reader = csv_lib.DictReader(io.StringIO(csv))
    for row in reader:
        # Schema flexibility - the column names have varied a bit historically
        cid = (row.get('client_id') or row.get('clientId') or row.get('id') or '').strip().lower()
        name = (row.get('name') or row.get('display_name') or row.get('client_name') or '').strip()
        if not cid:
            continue
        apps[cid] = {
            'name': name or cid,
            'publisher': 'Microsoft',
            'foci': True,
            'notes': 'FOCI client. Refresh tokens are family refresh tokens (FRTs) redeemable across all FOCI clients - a stolen FRT effectively grants the union of all FOCI scopes.',
        }

    print(f'  Got {len(apps)} FOCI clients from Secureworks')

    # Merge in adjacent apps. FOCI wins if there's a collision (defensive).
    for cid, info in ADJACENT_APPS.items():
        if cid not in apps:
            apps[cid.lower()] = info

    out = DATA / 'entra_known_apps.json'
    out.write_text(json.dumps(apps, indent=2, sort_keys=True))
    foci_count = sum(1 for v in apps.values() if v.get('foci'))
    print(f'  -> {out} ({len(apps)} apps, {foci_count} FOCI, {out.stat().st_size:,} bytes)')


# -----------------------------------------------------------------------------
# Claims and high-risk scopes - hand-curated, never overwritten
# -----------------------------------------------------------------------------

def verify_curated_files():
    """Make sure the hand-curated files exist; warn if they're stale."""
    for fname in ('entra_claims_reference.json', 'entra_high_risk_scopes.json'):
        p = DATA / fname
        if not p.exists():
            print(f'  WARN: {fname} is missing - hand-curated, must be re-created manually')
            continue
        try:
            json.load(p.open())
            print(f'  {fname} exists and is valid JSON ({p.stat().st_size:,} bytes)')
        except Exception as e:
            print(f'  ERROR: {fname} is corrupt: {e}', file=sys.stderr)
            sys.exit(1)


def main():
    print('=== Token decoder reference data refresh ===\n')
    failed = []
    for label, fn in [('wids', build_wids_json), ('known apps', build_known_apps_json)]:
        try:
            fn()
            print()
        except Exception as e:
            print(f'  ERROR refreshing {label}: {e}', file=sys.stderr)
            failed.append(label)
    print('Curated reference files:')
    verify_curated_files()
    if failed:
        print(f'\n{len(failed)} refresh(es) failed: {failed}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
