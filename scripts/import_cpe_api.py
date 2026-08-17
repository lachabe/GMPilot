#!/usr/bin/env python3
"""
Import complet du dictionnaire CPE depuis l'API NVD.
~1.75M entrées, paginé par 2000, ~1h30 sans API key.

Usage:
  .venv/bin/python scripts/import_cpe_api.py
  .venv/bin/python scripts/import_cpe_api.py --api-key YOUR_KEY   # 10x plus rapide
  .venv/bin/python scripts/import_cpe_api.py --resume              # reprend où ça s'est arrêté
"""
import sys
import os
import json
import time
import logging
import argparse
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
RESULTS_PER_PAGE = 2000
RATE_LIMIT_NO_KEY = 6.0
RATE_LIMIT_WITH_KEY = 0.6
MAX_RETRIES = 10


def fetch_page(start_index, api_key=None):
    """Télécharge une page de CPEs depuis l'API NVD avec retry."""
    url = f"{NVD_CPE_API}?resultsPerPage={RESULTS_PER_PAGE}&startIndex={start_index}"
    headers = {"Accept": "application/json", "User-Agent": "GMPilot-CPE/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(MAX_RETRIES):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            wait = (attempt + 1) * 30
            logger.warning(f"  Erreur page {start_index}: {e} — retry dans {wait}s ({attempt+1}/{MAX_RETRIES})")
            time.sleep(wait)
        except Exception as e:
            logger.error(f"  Erreur inattendue: {e}")
            time.sleep(30)

    return None


def parse_products(products):
    """Parse la liste products de l'API NVD en tuples pour insertion."""
    batch = []
    for p in products:
        cpe = p.get("cpe", {})
        cpe_name = cpe.get("cpeName", "")
        parts = cpe_name.split(":")
        if len(parts) < 6:
            continue

        titles = cpe.get("titles", [])
        title = ""
        for t in titles:
            if t.get("lang", "en").startswith("en"):
                title = t.get("title", "")
                break
        if not title and titles:
            title = titles[0].get("title", "")

        batch.append((
            cpe_name,
            parts[2],
            parts[3],
            parts[4],
            parts[5] if parts[5] != "*" else "",
            parts[6] if len(parts) > 6 and parts[6] != "*" else "",
            title,
            cpe.get("created", ""),
            cpe.get("lastModified", ""),
        ))
    return batch


def main():
    parser = argparse.ArgumentParser(description="Import CPE dictionary depuis l'API NVD")
    parser.add_argument("--api-key", help="Clé API NVD (optionnel, augmente le rate limit)")
    parser.add_argument("--resume", action="store_true", help="Reprend depuis le dernier index importé")
    parser.add_argument("--full", action="store_true", help="Reparcourt tout (comble les pages skippées)")
    args = parser.parse_args()

    rate_limit = RATE_LIMIT_WITH_KEY if args.api_key else RATE_LIMIT_NO_KEY

    from app import create_app
    app = create_app()

    with app.app_context():
        from app.db import connect_db

        conn = connect_db()
        current_count = conn.execute("SELECT COUNT(*) FROM cpe_dictionary").fetchone()[0]
        conn.close()

        start_index = 0
        if args.resume and current_count > 0 and not args.full:
            start_index = current_count
            logger.info(f"Reprise depuis l'index {start_index} ({current_count} déjà en base)")
        elif args.full:
            logger.info(f"Reparcours complet ({current_count} déjà en base, INSERT OR REPLACE)")
        else:
            logger.info(f"Import complet ({current_count} déjà en base)")

        # Première page pour connaître le total
        logger.info(f"Téléchargement page 1 (index {start_index})...")
        data = fetch_page(start_index, args.api_key)
        if not data:
            logger.error("Impossible de joindre l'API NVD")
            sys.exit(1)

        total_results = data.get("totalResults", 0)
        total_pages = (total_results + RESULTS_PER_PAGE - 1) // RESULTS_PER_PAGE
        estimated_time = (total_results - start_index) / RESULTS_PER_PAGE * rate_limit
        logger.info(f"Total: {total_results} CPEs, {total_pages} pages")
        logger.info(f"Estimation: ~{estimated_time / 60:.0f} minutes")

        # Traiter la première page
        batch = parse_products(data.get("products", []))
        total_imported = 0

        if batch:
            conn = connect_db()
            conn.executemany(
                """INSERT OR REPLACE INTO cpe_dictionary
                     (cpe_uri, cpe_type, vendor, product, version, update_str, title, created, last_modified)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                batch,
            )
            conn.commit()
            conn.close()
            total_imported += len(batch)

        start_index += RESULTS_PER_PAGE
        start_time = time.time()
        skipped_pages = 0

        while start_index < total_results:
            page_num = start_index // RESULTS_PER_PAGE + 1
            elapsed = time.time() - start_time
            rate = total_imported / max(1, elapsed) * 3600
            remaining_items = total_results - start_index
            remaining_min = remaining_items / max(1, rate / 3600) / 60
            logger.info(
                f"[{page_num}/{total_pages}] index={start_index}, "
                f"importés={total_imported} (base: {current_count + total_imported}), "
                f"{rate:.0f}/h, "
                f"restant ~{remaining_min:.0f}min"
            )

            time.sleep(rate_limit)
            data = fetch_page(start_index, args.api_key)

            if not data:
                logger.error(f"Échec page {page_num} après {MAX_RETRIES} tentatives — skip")
                skipped_pages += 1
                start_index += RESULTS_PER_PAGE
                continue

            batch = parse_products(data.get("products", []))
            if batch:
                conn = connect_db()
                conn.executemany(
                    """INSERT OR REPLACE INTO cpe_dictionary
                         (cpe_uri, cpe_type, vendor, product, version, update_str, title, created, last_modified)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    batch,
                )
                conn.commit()
                conn.close()
                total_imported += len(batch)

            start_index += RESULTS_PER_PAGE

        # Stats finales
        if skipped_pages:
            logger.warning(f"{skipped_pages} page(s) skippée(s) — relancez avec --full pour combler")
        conn = connect_db()
        total = conn.execute("SELECT COUNT(*) FROM cpe_dictionary").fetchone()[0]
        vendors = conn.execute("SELECT COUNT(DISTINCT vendor) FROM cpe_dictionary").fetchone()[0]
        products = conn.execute("SELECT COUNT(DISTINCT vendor || '/' || product) FROM cpe_dictionary").fetchone()[0]
        types = conn.execute(
            "SELECT cpe_type, COUNT(*) as cnt FROM cpe_dictionary GROUP BY cpe_type ORDER BY cnt DESC"
        ).fetchall()
        conn.close()

        elapsed = time.time() - start_time
        logger.info(f"\nTerminé en {elapsed / 60:.0f} minutes")
        logger.info(f"  Total en base: {total}")
        logger.info(f"  Vendors: {vendors}")
        logger.info(f"  Products: {products}")
        for t in types:
            label = {"a": "Applications", "o": "OS", "h": "Hardware"}.get(t[0], t[0])
            logger.info(f"  {label}: {t[1]}")


if __name__ == "__main__":
    main()
