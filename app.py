"""JWT-põhise autentimisega mini-API (Flask + PyJWT).

Lõpp-punktid:
    POST /login    – kontrollib kasutajanime ja parooli, tagastab JWT
    GET  /profiil  – vajab kehtivat tokenit, tagastab tokeni andmed
    GET  /admin    – vajab tokenit, milles role == "admin"
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

# Salavõti tuleb keskkonnamuutujast, koodis seda ei ole.
SALAVOTI = os.environ.get("JWT_SALAVOTI")
if not SALAVOTI or len(SALAVOTI) < 32:
    sys.exit("Viga: määra keskkonnamuutuja JWT_SALAVOTI (vähemalt 32 märki).")

# Server lubab ainult ühte algoritmi.
ALGORITM = "HS256"

# Tokeni kehtivus sekundites (vaikimisi 5 minutit). Aegunud tokeni
# testimiseks võib selle ajutiselt lühikeseks panna, nt TOKEN_KEHTIVUS_SEK=10.
KEHTIVUS = timedelta(seconds=int(os.environ.get("TOKEN_KEHTIVUS_SEK", "300")))

# Testkasutajad. Paroolid hoitakse räsitult, nagu päris rakenduses
# (pbkdf2, sest macOS-i süsteemse Pythoni hashlib-is scrypt puudub).
def rasi(parool):
    return generate_password_hash(parool, method="pbkdf2:sha256")


KASUTAJAD = {
    "kati": {"id": "2001", "roll": "student", "parool": rasi("kati123")},
    "peeter": {"id": "1", "roll": "admin", "parool": rasi("admin456")},
}

app = Flask(__name__)
app.json.ensure_ascii = False


def viga(tekst, kood):
    vastus = jsonify(viga=tekst)
    vastus.status_code = kood
    if kood == 401:
        vastus.headers["WWW-Authenticate"] = 'Bearer realm="mini-api"'
    return vastus


@app.post("/login")
def login():
    andmed = request.get_json(silent=True) or {}
    nimi = andmed.get("kasutajanimi")
    parool = andmed.get("parool")
    kasutaja = KASUTAJAD.get(nimi)

    if not kasutaja or not isinstance(parool, str) or not check_password_hash(kasutaja["parool"], parool):
        return viga("Vale kasutajanimi või parool", 401)

    nyyd = datetime.now(timezone.utc)
    payload = {
        "sub": kasutaja["id"],
        "name": nimi,
        "role": kasutaja["roll"],
        "iat": nyyd,
        "exp": nyyd + KEHTIVUS,
    }
    token = jwt.encode(payload, SALAVOTI, algorithm=ALGORITM)
    return jsonify(token=token, kehtib_sekundit=int(KEHTIVUS.total_seconds()))


def vajab_tokenit(roll=None):
    """Dekoraator: kontrollib Bearer-tokenit ja soovi korral rolli."""

    def dekoraator(funktsioon):
        @wraps(funktsioon)
        def kontroll(*args, **kwargs):
            pais = request.headers.get("Authorization", "")
            skeem, _, token = pais.partition(" ")
            if skeem != "Bearer" or not token:
                return viga("Token puudub", 401)

            try:
                andmed = jwt.decode(
                    token,
                    SALAVOTI,
                    algorithms=[ALGORITM],
                    options={"require": ["sub", "role", "exp"]},
                )
            except jwt.ExpiredSignatureError:
                return viga("Token on aegunud", 401)
            except jwt.InvalidTokenError:
                return viga("Vigane token", 401)

            if roll and andmed.get("role") != roll:
                return viga("Õigused puuduvad", 403)

            return funktsioon(andmed, *args, **kwargs)

        return kontroll

    return dekoraator


@app.get("/profiil")
@vajab_tokenit()
def profiil(andmed):
    return jsonify(andmed)


@app.get("/admin")
@vajab_tokenit(roll="admin")
def admin(andmed):
    return jsonify(teade=f"Tere tulemast admini lehele, {andmed['name']}!")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
