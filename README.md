# SOC Log Analyzer

Narzędzie w Pythonie do automatycznego wykrywania podejrzanej aktywności
w logach systemowych i logach serwera WWW — symuluje pierwszy etap pracy
analityka SOC (Security Operations Center) L1: **triage alertów bezpieczeństwa**.

## Co wykrywa

| Zagrożenie | Źródło | Metoda wykrywania |
|---|---|---|
| Brute force SSH | `auth.log` | Zliczanie nieudanych logowań z jednego IP w ustalonym progu |
| Udany atak po brute force | `auth.log` | Korelacja: IP atakujące → późniejsze udane logowanie z tego samego IP |
| Skanowanie / rekonesans | `access.log` | Wykrywanie wielu odpowiedzi 404 z jednego IP, ze szczególnym naciskiem na typowe ścieżki ataku (`/wp-admin`, `/.env`, `/phpmyadmin`) |
| SQL Injection | `access.log` | Dopasowanie wzorców (`OR '1'='1`, `DROP TABLE`, `UNION SELECT`) po dekodowaniu URL |
| XSS (Cross-Site Scripting) | `access.log` | Dopasowanie wzorców (`<script>`, `onerror=`, `javascript:`) po dekodowaniu URL |

## Dlaczego to ma znaczenie

Ręczne przeglądanie tysięcy linii logów jest tym, co realnie robi analityk
SOC L1 na początku kariery. To narzędzie automatyzuje pierwszy filtr —
zamiast czytać każdą linię, dostajesz gotowy raport z tym, co wymaga uwagi.

Wzorce wykrywania (progi, sygnatury ataków) są w pełni konfigurowalne
na górze pliku `log_analyzer.py`.

## Instalacja

Projekt nie wymaga zewnętrznych bibliotek — korzysta wyłącznie
z biblioteki standardowej Pythona 3.

```bash
git clone https://github.com/Rhaave/soc-log-analyzer.git
cd soc-log-analyzer
python3 log_analyzer.py
```

## Użycie

Domyślnie analizuje przykładowe logi z folderu `sample_logs/`:

```bash
python3 log_analyzer.py
```

Możesz wskazać własne pliki logów:

```bash
python3 log_analyzer.py --auth /var/log/auth.log --access /var/log/apache2/access.log
```

## Przykładowy output

```
######################################################################
#  SOC LOG ANALYZER — RAPORT BEZPIECZENSTWA
######################################################################

======================================================================
  1. ANALIZA LOGOWAN SSH (auth.log)
======================================================================
Przeanalizowano 20 zdarzen logowania.

[!] WYKRYTO 1 PODEJRZANY(CH) ADRES(OW) IP:

  IP: 192.168.1.50
    Liczba nieudanych prob: 12
    Testowane konta: admin, root, test

  [KRYTYCZNE] UDANE LOGOWANIE PO SERII NIEUDANYCH PROB:
    -> IP 192.168.1.50 zalogowal sie jako 'root'!
       To wyglada na SKUTECZNY atak brute-force.
```

## Struktura projektu

```
soc-log-analyzer/
├── log_analyzer.py       # główny skrypt analizy
├── sample_logs/
│   ├── auth.log          # przykładowy log SSH z zaszytym atakiem brute-force
│   └── access.log        # przykładowy log WWW z zaszytym skanowaniem + SQLi + XSS
└── README.md
```

## Możliwe rozszerzenia (roadmap)

- [ ] Eksport raportu do CSV / JSON
- [ ] Analiza logów w oknach czasowych (np. "50 prób w 60 sekund" zamiast sumy całkowitej)
- [ ] Integracja z prawdziwym SIEM (np. wysyłka alertów do Slacka/e-mail)
- [ ] Wsparcie dla logów w formacie JSON (nowoczesne systemy logowania)

## Autor

Projekt stworzony jako część portfolio technicznego w ramach przygotowań
do pracy w obszarze Security Operations / Cybersecurity.
