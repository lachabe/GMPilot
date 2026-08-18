#!/usr/bin/env python3
"""
Import initial du dictionnaire CPE depuis le dump NVD.
Supporte les formats :
  - nvdcpematch-2.0.tar.gz (contient un JSON)
  - .json direct

Usage:
  .venv/bin/python scripts/import_cpe.py nvdcpematch-2.0.tar.gz
  .venv/bin/python scripts/import_cpe.py cpematch.json
"""
import sys
import os
import json
import tarfile
import gzip
import logging
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BATCH_SIZE = 5000


def parse_cpe_uri(cpe_name: str) -> dict | None:
    """Parse cpe:2.3:type:vendor:product:version:update:... en dict."""
    parts = cpe_name.split(":")
    if len(parts) < 6:
        return None
    return {
        "cpe_uri": cpe_name,
        "cpe_type": parts[2],
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5] if parts[5] != "*" else "",
        "update_str": parts[6] if len(parts) > 6 and parts[6] != "*" else "",
    }


def extract_cpes_from_match_data(data) -> list[dict]:
    """Extrait les CPEs depuis le format nvdcpematch-2.0."""
    cpes = []
    match_strings = data.get("matchStrings", data.get("matches", []))

    for item in match_strings:
        match_data = item.get("matchString", item)
        criteria = match_data.get("criteria", match_data.get("cpe23Uri", ""))
        if not criteria:
            continue

        parsed = parse_cpe_uri(criteria)
        if not parsed:
            continue

        parsed["created"] = match_data.get("created", "")
        parsed["last_modified"] = match_data.get("lastModified", "")
        cpes.append(parsed)

    return cpes


def extract_cpes_from_products(data) -> list[dict]:
    """Extrait les CPEs depuis le format API products."""
    cpes = []
    products = data.get("products", [])

    for p in products:
        cpe = p.get("cpe", {})
        cpe_name = cpe.get("cpeName", "")
        if not cpe_name:
            continue

        parsed = parse_cpe_uri(cpe_name)
        if not parsed:
            continue

        titles = cpe.get("titles", [])
        title = ""
        for t in titles:
            if t.get("lang", "en").startswith("en"):
                title = t.get("title", "")
                break
        if not title and titles:
            title = titles[0].get("title", "")

        parsed["title"] = title
        parsed["created"] = cpe.get("created", "")
        parsed["last_modified"] = cpe.get("lastModified", "")
        cpes.append(parsed)

    return cpes


def load_json_from_file(filepath: str):
    """Charge le JSON depuis un fichier .json, .gz ou .tar.gz."""
    logger.info(f"Chargement de {filepath}...")

    if filepath.endswith(".tar.gz") or filepath.endswith(".tgz"):
        with tarfile.open(filepath, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".json"):
                    logger.info(f"  Extraction de {member.name} ({member.size / 1024 / 1024:.1f} MB)")
                    f = tar.extractfile(member)
                    if f:
                        return json.load(f)
            raise ValueError("Aucun fichier JSON trouvé dans l'archive")

    elif filepath.endswith(".gz"):
        with gzip.open(filepath, "rt", encoding="utf-8") as f:
            return json.load(f)

    else:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/import_cpe.py <fichier.tar.gz|fichier.json>")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"Fichier introuvable: {filepath}")
        sys.exit(1)

    from app import create_app
    app = create_app()

    with app.app_context():
        from app.db import connect_db

        data = load_json_from_file(filepath)

        # Détecter le format
        if "matchStrings" in data or "matches" in data:
            logger.info("Format détecté: nvdcpematch")
            cpes = extract_cpes_from_match_data(data)
        elif "products" in data:
            logger.info("Format détecté: NVD products API")
            cpes = extract_cpes_from_products(data)
        else:
            logger.error(f"Format non reconnu. Clés: {list(data.keys())[:5]}")
            sys.exit(1)

        logger.info(f"{len(cpes)} entrées CPE extraites")

        # Dédupliquer par cpe_uri
        seen = {}
        for c in cpes:
            uri = c["cpe_uri"]
            if uri not in seen:
                seen[uri] = c

        unique = list(seen.values())
        logger.info(f"{len(unique)} entrées uniques (après dédup)")

        # Insertion par batch
        conn = connect_db()
        inserted = 0
        start = time.time()

        for i in range(0, len(unique), BATCH_SIZE):
            batch = unique[i:i + BATCH_SIZE]
            conn.executemany(
                """INSERT OR REPLACE INTO cpe_dictionary
                     (cpe_uri, cpe_type, vendor, product, version, update_str, title, created, last_modified)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [(c["cpe_uri"], c["cpe_type"], c["vendor"], c["product"],
                  c.get("version", ""), c.get("update_str", ""), c.get("title", ""),
                  c.get("created", ""), c.get("last_modified", ""))
                 for c in batch],
            )
            conn.commit()
            inserted += len(batch)
            elapsed = time.time() - start
            logger.info(f"  {inserted}/{len(unique)} ({inserted * 100 // len(unique)}%) — {elapsed:.0f}s")

        # Stats
        types = conn.execute(
            "SELECT cpe_type, COUNT(*) as cnt FROM cpe_dictionary GROUP BY cpe_type ORDER BY cnt DESC"
        ).fetchall()
        vendors = conn.execute("SELECT COUNT(DISTINCT vendor) FROM cpe_dictionary").fetchone()[0]
        products = conn.execute("SELECT COUNT(DISTINCT vendor || '/' || product) FROM cpe_dictionary").fetchone()[0]

        logger.info("\nRésumé:")
        logger.info(f"  Total: {inserted} entrées CPE")
        logger.info(f"  Vendors: {vendors}")
        logger.info(f"  Products: {products}")
        for t in types:
            label = {"a": "Applications", "o": "OS", "h": "Hardware"}.get(t[0], t[0])
            logger.info(f"  {label}: {t[1]}")

        conn.close()
        logger.info(f"Terminé en {time.time() - start:.0f}s")


if __name__ == "__main__":
    main()
