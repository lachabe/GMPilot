#!/usr/bin/env python3
"""
Import historique — récupère tous les rapports passés depuis GVM
et les injecte dans la DB pour reconstruire l'antériorité.

Usage:
  .venv/bin/python scripts/import_history.py --username admin --password xxx

  Options:
    --dry-run     Liste les rapports sans importer
    --limit N     Limite à N rapports par tâche (défaut: tous)
"""
import sys
import os
import argparse
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

RESULTS_FILTER = "rows=-1 min_qod=70 apply_overrides=1 levels=mhc sort-reverse=severity"


def main():  # noqa: C901 — script one-off GVM-couplé, non testé : refactor non prioritaire
    parser = argparse.ArgumentParser(description="Import historique des rapports GVM")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--dry-run", action="store_true", help="Liste sans importer")
    parser.add_argument("--limit", type=int, default=0, help="Max rapports par tâche (0=tous)")
    parser.add_argument("--reports", nargs="+", help="Liste d'IDs de rapports à importer directement")
    args = parser.parse_args()

    from app import create_app
    app = create_app()

    with app.app_context():
        from app.gvm_client import gmp_session
        from app.db import (connect_db, is_report_imported, import_gmp_results,
                            mark_report_imported, enrich_and_score)

        conn = connect_db()

        with gmp_session(args.username, args.password, timeout=600) as gmp:
            logger.info("Connexion GMP OK")

            if args.reports:
                # Mode direct : importer une liste de report IDs
                report_ids = args.reports
                logger.info(f"{len(report_ids)} rapports à importer")

                for i, report_id in enumerate(report_ids):
                    already = conn.execute(
                        "SELECT 1 FROM scan_imports WHERE report_id=?", (report_id,)
                    ).fetchone()
                    if already:
                        logger.info(f"[{i+1}/{len(report_ids)}] {report_id[:8]}… — déjà importé, skip")
                        continue

                    if args.dry_run:
                        logger.info(f"[{i+1}/{len(report_ids)}] {report_id[:8]}… (dry-run)")
                        continue

                    logger.info(f"[{i+1}/{len(report_ids)}] {report_id[:8]}… — téléchargement...")
                    try:
                        # Récupérer le rapport pour extraire task_name et date
                        report_xml = gmp.get_report(report_id)
                        rpt = report_xml.find(".//report")
                        inner = rpt.find("report") if rpt is not None else None
                        src = inner if inner is not None else rpt

                        parent = src if src is not None else rpt
                        task_el = parent.find("task") if parent is not None else None
                        task_id = task_el.get("id", "") if task_el is not None else ""
                        task_name = task_el.findtext("name") or task_id if task_el is not None else "Unknown"
                        scan_date = src.findtext("timestamp") or "" if src is not None else ""

                        results_xml = gmp.get_results(
                            filter_string=f"{RESULTS_FILTER} report_id={report_id}"
                        )
                        seen_ids, count = import_gmp_results(
                            conn, results_xml, task_id, task_name, report_id, scan_date
                        )
                        mark_report_imported(conn, task_id, task_name, report_id, scan_date, count)
                        logger.info(f"  → {task_name} | {scan_date[:10]} | {count} résultats")
                    except Exception as e:
                        logger.error(f"  → Erreur: {e}")

            else:
                # Mode auto : parcourir toutes les tâches et tous leurs rapports
                logger.info("Récupération des tâches...")
                tasks_xml = gmp.get_tasks(filter_string="rows=-1 details=1")
                tasks = tasks_xml.findall(".//task")
                logger.info(f"{len(tasks)} tâches trouvées")

                for task in tasks:
                    task_id = task.get("id", "")
                    task_name = task.findtext("name") or task_id
                    if not task_id:
                        continue

                    logger.info(f"\n{'='*60}")
                    logger.info(f"Tâche: {task_name} ({task_id})")

                    reports_xml = gmp.get_reports(
                        filter_string=f"task_id={task_id} rows=-1 sort=date"
                    )
                    reports = reports_xml.findall(".//report")

                    report_list = []
                    for r in reports:
                        rid = r.get("id", "")
                        ts = r.findtext("timestamp") or r.findtext("creation_time") or ""
                        inner = r.find("report")
                        if inner is not None:
                            ts = inner.findtext("timestamp") or ts
                        if rid and ts:
                            report_list.append({"id": rid, "date": ts})

                    report_list.sort(key=lambda x: x["date"])
                    if args.limit > 0:
                        report_list = report_list[:args.limit]

                    logger.info(f"  {len(report_list)} rapports")

                    for i, rpt in enumerate(report_list):
                        report_id = rpt["id"]
                        scan_date = rpt["date"]

                        if is_report_imported(conn, task_id, report_id):
                            logger.info(f"  [{i+1}/{len(report_list)}] {scan_date[:10]} — skip")
                            continue

                        if args.dry_run:
                            logger.info(f"  [{i+1}/{len(report_list)}] {scan_date[:10]} — {report_id[:8]}… (dry-run)")
                            continue

                        logger.info(f"  [{i+1}/{len(report_list)}] {scan_date[:10]} — téléchargement...")
                        try:
                            results_xml = gmp.get_results(
                                filter_string=f"{RESULTS_FILTER} report_id={report_id}"
                            )
                            seen_ids, count = import_gmp_results(
                                conn, results_xml, task_id, task_name, report_id, scan_date
                            )
                            mark_report_imported(conn, task_id, task_name, report_id, scan_date, count)
                            logger.info(f"    → {count} résultats")
                        except Exception as e:
                            logger.error(f"    → Erreur: {e}")

        if not args.dry_run:
            # Résolution : pour chaque tâche, trouver les findings du dernier rapport
            # et marquer comme résolus ceux qui n'y sont plus
            logger.info("\nRésolution des vulnérabilités disparues...")
            from app.db import resolve_stale_findings

            task_ids = [r[0] for r in conn.execute(
                "SELECT DISTINCT task_id FROM scan_imports"
            ).fetchall()]

            total_resolved = 0
            for tid in task_ids:
                last_report = conn.execute(
                    "SELECT report_id, scan_date FROM scan_imports WHERE task_id=? ORDER BY scan_date DESC LIMIT 1",
                    (tid,)
                ).fetchone()
                if not last_report:
                    continue

                seen_in_last = {r[0] for r in conn.execute(
                    "SELECT finding_id FROM sightings WHERE report_id=?",
                    (last_report[0],)
                ).fetchall()}

                resolved = resolve_stale_findings(conn, tid, seen_in_last,
                                                  resolved_at=last_report["scan_date"])
                if resolved:
                    task_name = conn.execute(
                        "SELECT task_name FROM scan_imports WHERE task_id=? LIMIT 1", (tid,)
                    ).fetchone()[0]
                    logger.info(f"  {task_name}: {resolved} résolues")
                    total_resolved += resolved

            logger.info(f"Total résolues: {total_resolved}")

            logger.info("\nEnrichissement et scoring...")
            enrich_and_score(conn)

            total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            active = conn.execute("SELECT COUNT(*) FROM findings WHERE status='active'").fetchone()[0]
            resolved_count = conn.execute("SELECT COUNT(*) FROM findings WHERE status='resolved'").fetchone()[0]
            sightings = conn.execute("SELECT COUNT(*) FROM sightings").fetchone()[0]
            imports = conn.execute("SELECT COUNT(*) FROM scan_imports").fetchone()[0]
            logger.info("\nRésumé:")
            logger.info(f"  Rapports importés: {imports}")
            logger.info(f"  Sightings totaux:  {sightings}")
            logger.info(f"  Findings totaux:   {total} ({active} actifs, {resolved_count} résolus)")

        conn.close()
        logger.info("Terminé.")


if __name__ == "__main__":
    main()
