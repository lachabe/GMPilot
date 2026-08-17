"""
Télécharge les assets statiques localement pour éliminer toute dépendance CDN.

Usage : python download_static.py
À lancer UNE FOIS avant le premier démarrage.
"""
import urllib.request, os

STATIC_DIR = os.path.join(os.path.dirname(__file__), "app", "static")
VENDOR_DIR = os.path.join(STATIC_DIR, "vendor")
os.makedirs(VENDOR_DIR, exist_ok=True)

TABLER_VERSION = "1.4.0"
TABLER_ICONS_VERSION = "3.26.0"
CHARTJS_VERSION = "4.4.1"

ASSETS = [
    # ── Tabler Core ──────────────────────────────────────────────────────────
    {
        "url": f"https://cdn.jsdelivr.net/npm/@tabler/core@{TABLER_VERSION}/dist/css/tabler.min.css",
        "dest": f"tabler-{TABLER_VERSION}.min.css",
    },
    {
        "url": f"https://cdn.jsdelivr.net/npm/@tabler/core@{TABLER_VERSION}/dist/css/tabler.min.css.map",
        "dest": "tabler.min.css.map",
    },
    {
        "url": f"https://cdn.jsdelivr.net/npm/@tabler/core@{TABLER_VERSION}/dist/js/tabler.min.js",
        "dest": f"tabler-{TABLER_VERSION}.min.js",
    },
    {
        "url": f"https://cdn.jsdelivr.net/npm/@tabler/core@{TABLER_VERSION}/dist/js/tabler.min.js.map",
        "dest": "tabler.min.js.map",
    },
    # ── Tabler Icons (webfont) ───────────────────────────────────────────────
    {
        "url": f"https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@{TABLER_ICONS_VERSION}/dist/tabler-icons.min.css",
        "dest": f"tabler-icons-{TABLER_ICONS_VERSION}.min.css",
    },
    {
        "url": f"https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@{TABLER_ICONS_VERSION}/dist/fonts/tabler-icons.woff2",
        "dest": "fonts/tabler-icons.woff2",
    },
    {
        "url": f"https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@{TABLER_ICONS_VERSION}/dist/fonts/tabler-icons.woff",
        "dest": "fonts/tabler-icons.woff",
    },
    {
        "url": f"https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@{TABLER_ICONS_VERSION}/dist/fonts/tabler-icons.ttf",
        "dest": "fonts/tabler-icons.ttf",
    },
    # ── Chart.js ─────────────────────────────────────────────────────────────
    {
        "url": f"https://cdnjs.cloudflare.com/ajax/libs/Chart.js/{CHARTJS_VERSION}/chart.umd.min.js",
        "dest": f"chart.umd-{CHARTJS_VERSION}.min.js",
    },
]

print(f"Téléchargement des assets statiques (Tabler {TABLER_VERSION})...\n")
for asset in ASSETS:
    dest_path = os.path.join(VENDOR_DIR, asset["dest"])
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    if os.path.exists(dest_path):
        print(f"  ✓ {asset['dest']} (déjà présent)")
        continue
    print(f"  ↓ {asset['url']}")
    try:
        urllib.request.urlretrieve(asset["url"], dest_path)
        size_kb = os.path.getsize(dest_path) / 1024
        print(f"    → {asset['dest']}  ({size_kb:.0f} KB)")
    except Exception as e:
        print(f"    ✗ Erreur : {e}")

# ── Note : les chemins relatifs dans tabler-icons CSS (fonts/tabler-icons.*)
# résolvent correctement car le CSS et le dossier fonts/ sont sous /static/vendor/.
# Aucun patch nécessaire.

print(f"\n✅ Terminé. Relancez l'application avec : python run.py")
