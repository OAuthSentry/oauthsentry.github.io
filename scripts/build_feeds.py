#!/usr/bin/env python3
"""
OAuthSentry feed builder.

Reads data/sources.json, then for every service it:
  1. Loads the curated source as the source of truth (mthcht/awesome-lists).
  2. Loads the compliance_fill source if one is configured, and inserts every
     AppId that the curated source did NOT classify, defaulting it to
     compliance / info / "Microsoft first-party (via merill/microsoft-info)".
  3. Writes the merged set to data/<service>/oauth_apps.csv (the canonical site
     dataset) and emits per-service and combined feeds in feeds/.

Output:
  - data/<service>/oauth_apps.csv                                (merged source of truth)
  - feeds/<service>/<service>_{compliance,risky,malicious}.txt   (one app id per line)
  - feeds/<service>/<service>_{compliance,risky,malicious}.csv   (full rows)
  - feeds/<service>/<service>_all.json                           (full data, one JSON file)
  - feeds/all/all_{compliance,risky,malicious}.{txt,csv}         (combined across services)
  - feeds/all/all_index.json                                     (combined index for the site)
  - feeds/summary.json                                           (run summary + per-source provenance)

The curated source uses the label "legitimate" for non-malicious / non-abused apps;
OAuthSentry exposes that bucket as "compliance" (defender terminology - allowlist /
reference inventory). The mapping is applied at load time.
"""

import csv
import json
import re
import sys
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
FEEDS_DIR = ROOT / "feeds"
SOURCES_FILE = DATA_DIR / "sources.json"

CATEGORY_MAP = {
    "legitimate": "compliance",
    "compliance": "compliance",
    "risky": "risky",
    "malicious": "malicious",
}
CATEGORIES = ["compliance", "risky", "malicious"]
APPID_RE = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"

# Canonical OAuthSentry row schema (also the per-service oauth_apps.csv schema).
CANONICAL_FIELDS = [
    "appname", "appid",
    "metadata_category", "metadata_severity",
    "metadata_comment", "metadata_reference",
    "service", "_provenance",
]


def load_sources_config():
    with SOURCES_FILE.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_curated(local_path: Path, service: str, source_id: str, source_url: str | None = None) -> list[dict]:
    """mthcht's curated CSV. Returns a list of canonical rows.

    If source_url is given (the canonical upstream URL of this curated file),
    it is appended to every row's metadata_reference so consumers can trace the
    classification back to the curator. References are joined with ' | ',
    matching the mthcht convention the site already parses.
    """
    if not local_path.exists():
        return []
    rows = []
    with local_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            appid = (row.get("appid") or "").strip().lower()
            if not appid:
                continue
            cat_raw = (row.get("metadata_category") or "").strip().lower()
            # mthcht uses combined categories like "Phishing - compliance" - take the
            # last token after " - " as the canonical bucket; fall back to risky.
            cat_token = cat_raw.rsplit(" - ", 1)[-1].strip().lower()
            cat = CATEGORY_MAP.get(cat_token, "risky" if cat_raw else "compliance")

            existing_ref = (row.get("metadata_reference") or "").strip()
            if source_url and source_url not in existing_ref:
                if existing_ref and existing_ref.upper() not in ("N/A", "NA", "-"):
                    merged_ref = f"{existing_ref} | {source_url}"
                else:
                    merged_ref = source_url
            else:
                merged_ref = existing_ref

            rows.append({
                "appname":            (row.get("appname") or "").strip(),
                "appid":              appid,
                "metadata_category":  cat,
                "metadata_severity":  (row.get("metadata_severity") or "info").strip().lower(),
                "metadata_comment":   (row.get("metadata_comment") or "").strip(),
                "metadata_reference": merged_ref,
                "service":            service,
                "_provenance":        source_id,
            })
    return rows


def load_compliance_fill(local_path: Path, service: str, source_id: str) -> list[dict]:
    """merill's MicrosoftApps.csv. Every row → compliance / info."""
    if not local_path.exists():
        return []
    rows = []
    with local_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            # Schema: AppId, AppDisplayName, AppOwnerOrganizationId, Source
            appid = (row.get("AppId") or "").strip().lower()
            if not appid:
                continue
            display = (row.get("AppDisplayName") or "").strip()
            owner   = (row.get("AppOwnerOrganizationId") or "").strip()
            origin  = (row.get("Source") or "").strip()
            rows.append({
                "appname":            display or "(unnamed Microsoft first-party app)",
                "appid":              appid,
                "metadata_category":  "compliance",
                "metadata_severity":  "info",
                "metadata_comment":   f"Microsoft first-party app (owner tenant {owner}; via merill/microsoft-info, source={origin})",
                "metadata_reference": "https://github.com/merill/microsoft-info",
                "service":            service,
                "_provenance":        source_id,
            })
    return rows


def merge_service(service: str, curated_rows: list[dict], fill_rows: list[dict]) -> list[dict]:
    """Curated wins on every AppId conflict; fill rows only fill gaps."""
    by_id = {r["appid"]: r for r in curated_rows}
    added_from_fill = 0
    for r in fill_rows:
        if r["appid"] not in by_id:
            by_id[r["appid"]] = r
            added_from_fill += 1
    print(f"[{service}] curated={len(curated_rows)} fill={len(fill_rows)} new_from_fill={added_from_fill} merged_total={len(by_id)}")
    return sorted(by_id.values(), key=lambda r: (r["metadata_category"], r["appname"].lower(), r["appid"]))


def write_text_feed(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        fh.write("# OAuthSentry feed - one application id per line\n")
        fh.write(f"# generated: {datetime.now(timezone.utc).isoformat()}\n")
        fh.write(f"# count: {len(rows)}\n")
        for r in rows:
            fh.write(r["appid"] + "\n")


def write_csv_feed(path: Path, rows, fields=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = ["appname", "appid", "metadata_category", "metadata_severity",
                  "metadata_comment", "metadata_reference", "service"]
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in fields})


def write_json_feed(path: Path, rows):
    """Generic JSON feed writer for the existing service-level / all-services exports."""
    payload = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "count": len(rows),
        "items": rows,
    }
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


# ----------------------------------------------------------------------
# Static API generation
# ----------------------------------------------------------------------
#
# We expose a "REST-shaped" API as static JSON files served by GitHub Pages.
# The endpoint shape:
#   GET /feeds/api/v1/apps/<slug>.json     -> single app record (404 = unknown)
#   GET /feeds/api/v1/lookup.json          -> { slug: record }   - bulk by slug
#   GET /feeds/api/v1/lookup_by_appid.json -> { appid: record }  - bulk by raw id
#   GET /feeds/api/v1/meta.json            -> dataset metadata (counts, version, generated_at)
#
# The slug rule is documented and stable: lower-case the appid, then replace
# any run of non-[a-z0-9._-] characters with a single hyphen.
#
# This approach works because GitHub Pages serves .json as application/json
# and sets Access-Control-Allow-Origin: * by default, so the files are
# callable as a real API from any environment (curl, Python, browser JS).

SLUG_INVALID_RE = re.compile(r"[^a-z0-9._-]+")

def make_slug(appid: str) -> str:
    """Stable URL-safe slug for an OAuth App identifier.

    Defenders compute the same transform client-side to find the right endpoint.
    Lowercased; any run of characters outside [a-z0-9._-] becomes a single hyphen.
    Leading/trailing hyphens are stripped.
    """
    slug = SLUG_INVALID_RE.sub("-", appid.lower()).strip("-")
    return slug


def parse_references(reference_field: str) -> list[str]:
    """Split a metadata_reference string into a clean list of URLs."""
    if not reference_field:
        return []
    parts = re.split(r"\s*\|\s*|\s+-\s+|\s*,\s*", reference_field)
    return [p.strip() for p in parts if p.strip().startswith("http")]


def to_api_record(row: dict) -> dict:
    """Convert an internal row to a clean API response shape (no internal fields)."""
    return {
        "appid":      row["appid"],
        "appname":    row.get("appname") or "",
        "service":    row["service"],
        "category":   row["metadata_category"],
        "severity":   row.get("metadata_severity") or "info",
        "comment":    row.get("metadata_comment") or "",
        "references": parse_references(row.get("metadata_reference") or ""),
        "slug":       make_slug(row["appid"]),
    }


def write_api(all_rows: list[dict], summary: dict) -> dict:
    """Generate the static API tree under feeds/api/v1/. Returns API summary stats."""
    api_root = FEEDS_DIR / "api" / "v1"
    apps_dir = api_root / "apps"
    api_root.mkdir(parents=True, exist_ok=True)
    apps_dir.mkdir(parents=True, exist_ok=True)

    # Wipe old per-app files so removed entries don't linger
    for old in apps_dir.glob("*.json"):
        old.unlink()

    by_slug: dict[str, dict] = {}
    by_appid: dict[str, dict] = {}
    slug_collisions: list[tuple[str, str, str]] = []

    for row in all_rows:
        rec = to_api_record(row)
        slug = rec["slug"]
        appid = rec["appid"]

        # Slug collision detection: two distinct appids producing the same slug
        # (extremely unlikely but worth flagging in the build log)
        if slug in by_slug and by_slug[slug]["appid"] != appid:
            slug_collisions.append((slug, by_slug[slug]["appid"], appid))
            # Disambiguate by suffixing with the service name
            slug = f"{slug}--{rec['service']}"
            rec["slug"] = slug

        by_slug[slug]   = rec
        by_appid[appid] = rec

        # Per-app endpoint
        with (apps_dir / f"{slug}.json").open("w", encoding="utf-8") as fh:
            json.dump(rec, fh, indent=2, ensure_ascii=False)

    # Bulk lookups
    with (api_root / "lookup.json").open("w", encoding="utf-8") as fh:
        json.dump(by_slug, fh, indent=2, ensure_ascii=False)
    with (api_root / "lookup_by_appid.json").open("w", encoding="utf-8") as fh:
        json.dump(by_appid, fh, indent=2, ensure_ascii=False)

    # Dataset metadata
    meta = {
        "schema_version":  "1",
        "generated":       datetime.now(timezone.utc).isoformat(),
        "total_apps":      len(all_rows),
        "by_service":      {svc: d["total"] for svc, d in summary["services"].items()},
        "by_category":     summary["totals"],
        "endpoints": {
            "single_app":       "/feeds/api/v1/apps/{slug}.json",
            "lookup_by_slug":   "/feeds/api/v1/lookup.json",
            "lookup_by_appid":  "/feeds/api/v1/lookup_by_appid.json",
            "meta":             "/feeds/api/v1/meta.json",
        },
        "slug_rule": "lower-case the appid, then replace any run of characters outside [a-z0-9._-] with a single hyphen, strip leading/trailing hyphens",
        "license":   "see https://github.com/oauthsentry/oauthsentry.github.io/blob/main/LICENSE for project license; per-row references retain attribution to upstream curators (mthcht/awesome-lists, merill/microsoft-info, GitHub blog, etc.)",
    }
    with (api_root / "meta.json").open("w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, ensure_ascii=False)

    return {"apps_written": len(by_slug), "collisions": len(slug_collisions)}
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "count": len(rows),
        "items": rows,
    }
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def build():
    if not SOURCES_FILE.exists():
        print(f"no sources file at {SOURCES_FILE}", file=sys.stderr)
        sys.exit(1)

    cfg = load_sources_config()
    sources = cfg.get("sources", [])

    # Group sources by service
    by_service: dict[str, dict] = {}
    for src in sources:
        if src.get("role") in ("planned", None):
            continue
        svc = src.get("service") or src.get("id")
        by_service.setdefault(svc, {})[src["role"]] = src

    all_rows = []
    summary = {"services": {}, "totals": {c: 0 for c in CATEGORIES}, "sources": []}

    for service, roles in sorted(by_service.items()):
        curated_src = roles.get("curated")
        fill_src    = roles.get("compliance_fill")

        curated_rows = []
        fill_rows    = []
        if curated_src:
            curated_rows = load_curated(
                ROOT / curated_src["local"],
                service,
                curated_src["id"],
                source_url=curated_src.get("source_url"),
            )
            summary["sources"].append({**curated_src, "loaded_rows": len(curated_rows)})
        if fill_src:
            fill_rows = load_compliance_fill(ROOT / fill_src["local"], service, fill_src["id"])
            summary["sources"].append({**fill_src, "loaded_rows": len(fill_rows)})

        merged = merge_service(service, curated_rows, fill_rows)
        if not merged:
            print(f"[{service}] no rows; skipping")
            continue

        # Write the merged source-of-truth CSV (data/<service>/oauth_apps.csv)
        merged_csv = DATA_DIR / service / "oauth_apps.csv"
        write_csv_feed(merged_csv, merged)

        # Per-service feeds: filename includes the service name to avoid
        # collisions when defenders download multiple feeds into the same dir.
        # Pattern: feeds/<service>/<service>_<category>.{txt,csv}
        per_cat = {c: [r for r in merged if r["metadata_category"] == c] for c in CATEGORIES}
        for cat, rows in per_cat.items():
            base = FEEDS_DIR / service / f"{service}_{cat}"
            write_text_feed(base.with_suffix(".txt"), rows)
            write_csv_feed(base.with_suffix(".csv"), rows)
        write_json_feed(FEEDS_DIR / service / f"{service}_all.json", merged)

        summary["services"][service] = {
            "total":      len(merged),
            "compliance": len(per_cat["compliance"]),
            "risky":      len(per_cat["risky"]),
            "malicious":  len(per_cat["malicious"]),
            "curated_source":         curated_src["id"] if curated_src else None,
            "compliance_fill_source": fill_src["id"]    if fill_src    else None,
        }
        all_rows.extend(merged)

    # Combined feeds across services - same naming convention: all_<category>.{txt,csv}
    for cat in CATEGORIES:
        rows = [r for r in all_rows if r["metadata_category"] == cat]
        base = FEEDS_DIR / "all" / f"all_{cat}"
        write_text_feed(base.with_suffix(".txt"), rows)
        write_csv_feed(base.with_suffix(".csv"), rows)
        summary["totals"][cat] = len(rows)
    write_json_feed(FEEDS_DIR / "all" / "all_index.json", all_rows)

    summary["generated"]  = datetime.now(timezone.utc).isoformat()
    summary["total_apps"] = len(all_rows)
    with (FEEDS_DIR / "summary.json").open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    # Generate the static REST-shaped API tree under feeds/api/v1/
    api_stats = write_api(all_rows, summary)
    print(f"[api] wrote {api_stats['apps_written']} per-app JSON files "
          f"(slug collisions handled: {api_stats['collisions']})")

    print(json.dumps({k: v for k, v in summary.items() if k != "sources"}, indent=2))


if __name__ == "__main__":
    build()
