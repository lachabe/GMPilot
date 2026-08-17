"""Point d'entrée — GMPILOT"""
import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    debug = os.environ.get("FLASK_ENV") == "development"
    host  = "127.0.0.1" if debug else os.environ.get("FLASK_HOST", "127.0.0.1")
    port  = int(os.environ.get("FLASK_PORT", 5000))

    # SSL/TLS optionnel — définir FLASK_SSL_CERT et FLASK_SSL_KEY dans .env
    ssl_cert = os.environ.get("FLASK_SSL_CERT", "")
    ssl_key  = os.environ.get("FLASK_SSL_KEY", "")

    if ssl_cert and ssl_key:
        ssl_context = (ssl_cert, ssl_key)
    else:
        ssl_context = None

    app.run(debug=debug, host=host, port=port, ssl_context=ssl_context)
