# JWT mini-API

Väike Flask + PyJWT rakendus, mis näitab JWT-põhist autentimist ja rollipõhist ligipääsu.

| Lõpp-punkt | Kirjeldus | Vastused |
|---|---|---|
| `POST /login` | kontrollib kasutajanime ja parooli, tagastab JWT (`sub`, `name`, `role`, `iat`, `exp`) | 200, 401 |
| `GET /profiil` | ainult kehtiva tokeniga, tagastab tokeni andmed | 200, 401 |
| `GET /admin` | ainult tokeniga, milles `role` on `admin` | 200, 401, 403 |

Turvanõuded, mis on koodis täidetud:

- salavõti loetakse keskkonnamuutujast `JWT_SALAVOTI` (server ei käivitu, kui see puudub või on lühem kui 32 märki);
- server lubab ainult algoritmi `HS256` (`alg: none` ja teised algoritmid lükatakse tagasi);
- token kehtib 5 minutit (`exp`), kehtivust saab testimiseks muuta muutujaga `TOKEN_KEHTIVUS_SEK`;
- puuduv, vigane, võltsitud või aegunud token → **401**, õiguste puudumine → **403**;
- testkasutajate paroolid on hoitud räsitult.

## Testkasutajad

| Kasutajanimi | Parool | Roll |
|---|---|---|
| `kati` | `kati123` | `student` |
| `peeter` | `admin456` | `admin` |

## Käivitamine

Vaja on Pythonit 3.9+.

```bash
python3 -m venv venv
source venv/bin/activate          # Windowsis: venv\Scripts\activate
pip install -r requirements.txt

export JWT_SALAVOTI="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python app.py                     # http://127.0.0.1:5000
```

Windows PowerShellis määra salavõti nii: `$env:JWT_SALAVOTI = python -c "import secrets; print(secrets.token_urlsafe(48))"`.

## Käsitsi testimine curl-iga

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/json" \
  -d '{"kasutajanimi":"kati","parool":"kati123"}' | jq -r .token)

curl -i http://127.0.0.1:5000/profiil -H "Authorization: Bearer $TOKEN"   # 200
curl -i http://127.0.0.1:5000/admin   -H "Authorization: Bearer $TOKEN"   # 403
curl -i http://127.0.0.1:5000/profiil                                     # 401
```

## Automaatsed testid

```bash
./testid.sh
```

Skript käivitab ise kaks serverit (tavaline ja 2-sekundilise kehtivusega aegunud tokeni testiks), läbib kõik testjuhud T01–T10 ja salvestab iga juhu väljundi kausta [`toendid/`](toendid/).

| # | Testjuhtum | Lõpp-punkt | Oodatav |
|---|---|---|---|
| T01 | Edukas sisselogimine | `/login` | 200 |
| T02 | Vale parooliga sisselogimine | `/login` | 401 |
| T03 | Kehtiv token | `/profiil` | 200 |
| T04 | Token puudub | `/profiil` | 401 |
| T05 | Võltsitud token (role → admin, vana allkiri) | `/profiil` | 401 |
| T06 | Aegunud token | `/profiil` | 401 |
| T07 | Tavakasutaja token admini lõpp-punktil | `/admin` | 403 |
| T08 | Admini token | `/admin` | 200 |
| T09 | `alg: none` token | `/admin` | 401 |
| T10 | Teise võtmega allkirjastatud token | `/admin` | 401 |
