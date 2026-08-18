"""
Admin blueprint — Gestion des rôles et permissions.
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required
from app.auth.permissions import require_perm, PERMISSIONS, permissions_by_section
from app.auth.roles import load_all_roles, save_role, delete_role, get_role

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/roles")
@login_required
@require_perm("roles.read")
def roles_index():
    """Liste des rôles."""
    roles = load_all_roles()
    return render_template("admin/roles.html", roles=roles)


@admin_bp.route("/roles/new", methods=["GET", "POST"])
@login_required
@require_perm("roles.create")
def roles_create():
    """Créer un nouveau rôle."""
    if request.method == "POST":
        role_id = request.form.get("id", "").strip().lower().replace(" ", "_")
        if not role_id:
            flash("L'identifiant du rôle est requis.", "danger")
            return redirect(url_for("admin.roles_create"))

        role = {
            "id": role_id,
            "name": request.form.get("name", "").strip(),
            "description": request.form.get("description", "").strip(),
            "matching": {
                "ldap": {
                    "enabled": request.form.get("ldap_enabled") == "1",
                    "groups": [g.strip() for g in request.form.get("ldap_groups", "").splitlines() if g.strip()],
                },
                "oidc": {
                    "enabled": request.form.get("oidc_enabled") == "1",
                    "groups": [g.strip() for g in request.form.get("oidc_groups", "").splitlines() if g.strip()],
                },
            },
            "permissions": {
                perm: (request.form.get(f"perm_{perm}") == "1")
                for perm, _, _ in PERMISSIONS
            },
        }

        if save_role(role):
            flash(f"Rôle « {role['name']} » créé.", "success")
            return redirect(url_for("admin.roles_index"))
        flash("Erreur lors de la sauvegarde.", "danger")

    return render_template("admin/role_edit.html",
                           role=None,
                           sections=permissions_by_section(),
                           action="create")


@admin_bp.route("/roles/<role_id>/edit", methods=["GET", "POST"])
@login_required
@require_perm("roles.edit")
def roles_edit(role_id):
    """Modifier un rôle existant."""
    role = get_role(role_id)
    if role is None:
        flash("Rôle introuvable.", "danger")
        return redirect(url_for("admin.roles_index"))

    if request.method == "POST":
        role["name"] = request.form.get("name", "").strip()
        role["description"] = request.form.get("description", "").strip()
        role["matching"] = {
            "ldap": {
                "enabled": request.form.get("ldap_enabled") == "1",
                "groups": [g.strip() for g in request.form.get("ldap_groups", "").splitlines() if g.strip()],
            },
            "oidc": {
                "enabled": request.form.get("oidc_enabled") == "1",
                "groups": [g.strip() for g in request.form.get("oidc_groups", "").splitlines() if g.strip()],
            },
        }
        role["permissions"] = {
            perm: (request.form.get(f"perm_{perm}") == "1")
            for perm, _, _ in PERMISSIONS
        }

        if save_role(role):
            flash(f"Rôle « {role['name']} » mis à jour.", "success")
            return redirect(url_for("admin.roles_index"))
        flash("Erreur lors de la sauvegarde.", "danger")

    return render_template("admin/role_edit.html",
                           role=role,
                           sections=permissions_by_section(),
                           action="edit")


@admin_bp.route("/roles/<role_id>/delete", methods=["POST"])
@login_required
@require_perm("roles.delete")
def roles_delete(role_id):
    """Supprimer un rôle."""
    if delete_role(role_id):
        flash("Rôle supprimé.", "info")
    else:
        flash("Erreur lors de la suppression.", "danger")
    return redirect(url_for("admin.roles_index"))


# ── Résolutions DNS (édition manuelle des hostnames) ────────────────────────

@admin_bp.route("/dns")
@login_required
@require_perm("dns.manage")
def dns_index():
    """Page d'édition des résolutions DNS (compléter/corriger les hostnames)."""
    from app.db import get_db, dns_all_entries
    entries = dns_all_entries(get_db())
    total = len(entries)
    empty = sum(1 for e in entries if not (e["hostname"] or "").strip())
    manual = sum(1 for e in entries if e["manual"])
    stats = {"total": total, "resolved": total - empty, "empty": empty, "manual": manual}
    return render_template("admin/dns.html", entries=entries, stats=stats)


@admin_bp.route("/dns/save", methods=["POST"])
@login_required
@require_perm("dns.manage")
def dns_save():
    """Fixe manuellement le hostname d'une IP (édition d'une entrée ou ajout)."""
    import ipaddress
    from app.db import connect_db, set_dns_manual

    ip = (request.form.get("ip") or "").strip()
    hostname = (request.form.get("hostname") or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"ok": False, "error": "Adresse IP invalide"}), 400

    conn = connect_db()
    try:
        set_dns_manual(conn, ip, hostname)
    finally:
        conn.close()
    return jsonify({"ok": True, "ip": ip, "hostname": hostname or None, "manual": 1})


@admin_bp.route("/dns/reset", methods=["POST"])
@login_required
@require_perm("dns.manage")
def dns_reset():
    """Supprime une entrée : elle sera re-résolue au prochain scan incrémental."""
    from app.db import connect_db, reset_dns_entry

    ip = (request.form.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "IP manquante"}), 400

    conn = connect_db()
    try:
        reset_dns_entry(conn, ip)
    finally:
        conn.close()
    return jsonify({"ok": True, "ip": ip})


@admin_bp.route("/dns/import", methods=["POST"])
@login_required
@require_perm("dns.manage")
def dns_import():
    """Import en masse de résolutions manuelles (une ligne « IP;hostname »)."""
    import re
    import ipaddress
    from app.db import connect_db, import_dns_manual

    raw = request.form.get("data", "")
    pairs, invalid = [], 0
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = re.split(r"[;,\s]+", line, maxsplit=1)
        ip = parts[0].strip()
        host = parts[1].strip() if len(parts) > 1 else ""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            invalid += 1
            continue
        if host:
            pairs.append((ip, host))
        else:
            invalid += 1

    if not pairs:
        return jsonify({"ok": False, "error": "Aucune ligne valide (format : IP;hostname)"}), 400

    conn = connect_db()
    try:
        n = import_dns_manual(conn, pairs)
    finally:
        conn.close()
    return jsonify({"ok": True, "imported": n, "invalid": invalid})


@admin_bp.route("/dns/export.csv")
@login_required
@require_perm("dns.manage")
def dns_export_csv():
    """Export CSV de toutes les résolutions DNS."""
    import csv, io
    from datetime import datetime as _dt
    from flask import Response
    from app.db import get_db, dns_all_entries

    entries = dns_all_entries(get_db())

    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["IP", "Hostname", "Source", "Dernière résolution"])
    for e in entries:
        hostname = (e["hostname"] or "").strip()
        if e["manual"]:
            source = "Manuel"
        elif hostname:
            source = "Auto"
        else:
            source = "Vide"
        w.writerow([e["ip"], hostname, source, (e["resolved_at"] or "")[:19]])

    data = "﻿" + buf.getvalue()  # BOM UTF-8 → accents corrects dans Excel
    fname = f"resolutions_dns_{_dt.now():%Y%m%d}.csv"
    return Response(data, mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})
