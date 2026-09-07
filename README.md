# StegAnalyzer Pro — lokal backend (Etappe A–C)

Kjører de tunge forensic-verktøyene lokalt og serverer StegAnalyzer-HTML-en din
fra samme origin (ingen CORS). Alt går automatisk: lett analyse i nettleseren,
tungt i backend. I server-modus lyser en indikator, og «no data leaves your
browser» byttes til en ærlig melding.

Verktøy: **zsteg**, **steghide**, **binwalk -e**, **foremost**, **StegExpose**.

## 1. Installer systemverktøyene (Kali/WSL2)

```bash
sudo apt update
sudo apt install -y binwalk foremost steghide ruby ruby-dev default-jre
sudo gem install zsteg
```

`default-jre` gir Java, som StegExpose trenger.

## 2. Hent StegExpose (verifisert kommando)

StegExpose er en Java-JAR fra det offisielle repoet. Legg den i `tools/`:

```bash
mkdir -p tools
wget -O tools/StegExpose.jar https://raw.githubusercontent.com/b3dk7/StegExpose/master/StegExpose.jar
```

Backenden oppdager JAR-en automatisk (`/api/tools` viser `stegexpose` som
tilgjengelig først når både Java og JAR-en finnes). Dropper du dette steget,
kjører alt annet som normalt — bare uten StegExpose.

## 3. Installer Python-avhengigheter

```bash
pip install Flask --break-system-packages
# eller, hvis du står i mappa: pip install -r requirements.txt --break-system-packages
```

## 4. Legg fila på plass

- Kopier din **v3.7.0**-HTML til `templates/index.html`
- Legg til **én linje** rett før `</body>`:

```html
<script src="/static/steg-backend.js"></script>
```

## 5. Kjør

```bash
python app.py            # -> http://127.0.0.1:5000
```

Slipp inn et bilde — klientside-analysen kjører som før, og backend-verktøyene
fyrer automatisk under (de som passer filtypen). Embedded-scan-modulen får en
«▶ Kjør binwalk -e nå»-knapp når backend er til stede.

## Mappestruktur

```
steganalyzer/
├── app.py
├── analyzers.py
├── requirements.txt
├── README.md
├── templates/
│   └── index.html          (din fil + script-taggen)
├── static/
│   └── steg-backend.js
└── tools/
    └── StegExpose.jar      (fra steg 2)
```

## Endepunkter

| Rute | Hva |
|------|-----|
| `GET /` | HTML-en din |
| `GET /api/tools` | Hvilke verktøy som er installert |
| `POST /api/analyze` | Kjør ett verktøy (`tool=`, `file=`, valgfri `passphrase=`) |
| `GET /api/download/<job>` | Zip med filer fra binwalk/foremost |

## Disk-tak (krasj-vern)

`binwalk -e` og `foremost` kjøres med et **500 MB disk-tak**: pakker en
ondsinnet fil (zip-bombe) ut mer enn det, drepes hele prosess-gruppen og det
delvis utpakkede slettes umiddelbart. Dette verner din egen laptop og er
uavhengig av tilgangsherding (token/Docker/rate-limit) — det er fortsatt
Etappe D. Juster taket via `MAX_EXTRACT_BYTES` i `analyzers.py`.

## Gruppe-CTF (flere maskiner)

I `app.py`, bytt `host="127.0.0.1"` til `host="0.0.0.0"`. Da gjelder
`netsh`-port-forwardingen din fra WSL2-guiden. Ekte tilgangsherding kommer i
Etappe D — ikke eksponer dette mot utrygge nett ennå.

## Feilsøking

- **Ingen backend-panel:** åpner du via `file://`? Bruk `http://127.0.0.1:5000`.
- **Panelet sier «Fant ikke #file-input»:** juster ID-ene øverst i `steg-backend.js`.
- **stegexpose står som «mangler»:** mangler Java (`default-jre`) eller
  `tools/StegExpose.jar` (steg 2).
- **Et annet verktøy «mangler»:** installer det (steg 1), eller ignorer.
