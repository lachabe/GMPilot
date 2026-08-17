#!/usr/bin/env python3
"""
Résout les findings actifs qui ne sont plus dans le dernier rapport de chaque tâche.
À lancer après un import historique, ou manuellement en cas de doute.

Usage:
  .venv/bin/python scripts/resolve_findings.py
"""
import sys
import os
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def main():
    from app import create_app
    app = create_app()

    with app.app_context():
        from app.db import connect_db, resolve_stale_findings, enrich_and_score

        conn = connect_db()

        before = conn.execute("SELECT COUNT(*) FROM findings WHERE status='active'").fetchone()[0]
        logger.info(f"Findings actifs avant: {before}")

        task_ids = [r[0] for r in conn.execute(
            "SELECT DISTINCT task_id FROM scan_imports"
        ).fetchall()]

        total_resolved = 0
        for tid in task_ids:
            last_report = conn.execute(
                "SELECT report_id, task_name, scan_date FROM scan_imports WHERE task_id=? ORDER BY scan_date DESC LIMIT 1",
                (tid,)
            ).fetchone()
            if not last_report:
                continue

            seen_in_last = {r[0] for r in conn.execute(
                "SELECT finding_id FROM sightings WHERE report_id=?",
                (last_report["report_id"],)
            ).fetchall()}

            resolved = resolve_stale_findings(conn, tid, seen_in_last,
                                              resolved_at=last_report["scan_date"])
            if resolved:
                logger.info(f"  {last_report['task_name']}: {resolved} résolues")
                total_resolved += resolved

        after = conn.execute("SELECT COUNT(*) FROM findings WHERE status='active'").fetchone()[0]
        resolved_total = conn.execute("SELECT COUNT(*) FROM findings WHERE status='resolved'").fetchone()[0]

        logger.info(f"\nRésultat:")
        logger.info(f"  Résolues cette passe: {total_resolved}")
        logger.info(f"  Findings actifs:      {before} → {after}")
        logger.info(f"  Findings résolus:     {resolved_total}")

        if total_resolved > 0:
            logger.info("\nRe-enrichissement...")
            enrich_and_score(conn)

        conn.close()
        logger.info("Terminé.")


if __name__ == "__main__":
    main()
