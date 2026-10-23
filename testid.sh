#!/usr/bin/env bash
# Käivitab kõik testjuhud curl-iga ja salvestab iga juhu väljundi kausta toendid/.
# Kasutamine:  ./testid.sh
# Skript käivitab ise kaks serverit: tavalise (kehtivus 5 min, port 5000) ja
# lühikese kehtivusega (2 s, port 5001) aegunud tokeni testi jaoks.

set -u
cd "$(dirname "$0")"

PY="${PYTHON:-./venv/bin/python}"
export JWT_SALAVOTI="${JWT_SALAVOTI:-$("$PY" -c 'import secrets; print(secrets.token_urlsafe(48))')}"
URL="http://127.0.0.1:5000"
URL_LYHIKE="http://127.0.0.1:5001"
mkdir -p toendid
rm -f toendid/*.txt

PORT=5000 "$PY" app.py >/dev/null 2>&1 &
SERVER=$!
PORT=5001 TOKEN_KEHTIVUS_SEK=2 "$PY" app.py >/dev/null 2>&1 &
SERVER_LYHIKE=$!
trap 'kill $SERVER $SERVER_LYHIKE 2>/dev/null' EXIT

for u in "$URL" "$URL_LYHIKE"; do
  for _ in $(seq 50); do curl -s -o /dev/null "$u/profiil" && continue 2; sleep 0.2; done
  echo "Server $u ei käivitunud" >&2
  exit 1
done

LABIS=0
KOKKU=0

# testjuht <fail> <nimi> <oodatav kood> <curl argumendid...>
testjuht() {
  local fail="toendid/$1.txt" nimi="$2" oodatav="$3"
  shift 3
  local keha kood
  keha=$(curl -s -w $'\n%{http_code}' "$@")
  kood=$(tail -n1 <<<"$keha")
  keha=$(sed '$d' <<<"$keha")
  KOKKU=$((KOKKU + 1))
  local tulemus="EI LÄBINUD"
  [[ "$kood" == "$oodatav" ]] && tulemus="LÄBIS" && LABIS=$((LABIS + 1))
  {
    echo "== $nimi =="
    echo "Aeg:      $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "Päring:   curl $*" | sed -E 's/(Bearer )[A-Za-z0-9._-]{20,}/\1<token>/'
    echo "Oodatav:  $oodatav"
    echo "Tegelik:  $kood"
    echo "Vastus:   $keha"
    echo "Tulemus:  $tulemus"
  } | tee "$fail"
  echo
}

login() {
  curl -s -X POST "$1/login" -H "Content-Type: application/json" \
    -d "{\"kasutajanimi\":\"$2\",\"parool\":\"$3\"}" | jq -r .token
}

TOKEN_KATI=$(login "$URL" kati kati123)
TOKEN_PEETER=$(login "$URL" peeter admin456)

# Võltsing: payloadis role -> admin, allkiri jääb vanaks.
TOKEN_VOLTSITUD=$("$PY" - "$TOKEN_KATI" <<'EOF'
import base64, json, sys
pais, payload, allkiri = sys.argv[1].split(".")
andmed = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
andmed["role"] = "admin"
uus = base64.urlsafe_b64encode(json.dumps(andmed, separators=(",", ":")).encode()).rstrip(b"=").decode()
print(f"{pais}.{uus}.{allkiri}")
EOF
)

# alg: none – token ilma allkirjata.
TOKEN_NONE=$("$PY" - "$TOKEN_KATI" <<'EOF'
import base64, sys
_, payload, _ = sys.argv[1].split(".")
pais = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
print(f"{pais}.{payload}.")
EOF
)

# Token, mis on allkirjastatud vale võtmega.
TOKEN_VALE_VOTI=$("$PY" -c '
import time, jwt
print(jwt.encode({"sub": "1", "name": "peeter", "role": "admin", "exp": int(time.time()) + 300},
                 "see-ei-ole-serveri-salavoti-0123456789abcdef", algorithm="HS256"))')

# Aegunud token: lühikese kehtivusega server, ootame kuni token aegub.
TOKEN_AEGUNUD=$(login "$URL_LYHIKE" kati kati123)
sleep 3

testjuht T01_edukas_login "T01 Edukas sisselogimine" 200 \
  -X POST "$URL/login" -H "Content-Type: application/json" -d '{"kasutajanimi":"kati","parool":"kati123"}'
testjuht T02_vale_parool "T02 Vale parooliga sisselogimine" 401 \
  -X POST "$URL/login" -H "Content-Type: application/json" -d '{"kasutajanimi":"kati","parool":"vale"}'
testjuht T03_profiil_kehtiv "T03 /profiil kehtiva tokeniga" 200 \
  "$URL/profiil" -H "Authorization: Bearer $TOKEN_KATI"
testjuht T04_profiil_tokenita "T04 /profiil ilma tokenita" 401 \
  "$URL/profiil"
testjuht T05_profiil_voltsitud "T05 /profiil võltsitud tokeniga (role=admin, vana allkiri)" 401 \
  "$URL/profiil" -H "Authorization: Bearer $TOKEN_VOLTSITUD"
testjuht T06_profiil_aegunud "T06 /profiil aegunud tokeniga" 401 \
  "$URL_LYHIKE/profiil" -H "Authorization: Bearer $TOKEN_AEGUNUD"
testjuht T07_admin_student "T07 /admin tavakasutaja (student) tokeniga" 403 \
  "$URL/admin" -H "Authorization: Bearer $TOKEN_KATI"
testjuht T08_admin_admin "T08 /admin admini tokeniga" 200 \
  "$URL/admin" -H "Authorization: Bearer $TOKEN_PEETER"
testjuht T09_alg_none "T09 /admin tokeniga, kus alg=none" 401 \
  "$URL/admin" -H "Authorization: Bearer $TOKEN_NONE"
testjuht T10_vale_voti "T10 /admin teise võtmega allkirjastatud tokeniga" 401 \
  "$URL/admin" -H "Authorization: Bearer $TOKEN_VALE_VOTI"

echo "Kokku: $LABIS / $KOKKU testi läbis"
[[ $LABIS -eq $KOKKU ]]
