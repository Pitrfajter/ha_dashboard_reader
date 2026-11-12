# Bezpieczny eksport integracji Home Assistant — projekt

Status: **przygotowanie, bez instalacji**.

## Cel
Eksport oryginalnych plików `custom_components/bosch_homecom` do prywatnego repozytorium `Pitrfajter/bosch_homecom_custom` bez ręcznego kopiowania przez Samba.

## Etap 1 — audyt tylko do odczytu
- Lista plików, rozmiar, SHA-256 i liczba potencjalnych sekretów.
- Blokada dowiązań symbolicznych, plików za dużych i podejrzanych danych dostępowych.
- Pominięcie `__pycache__` i plików tymczasowych.
- Brak zwracania źródła lub sekretów przez usługę diagnostyczną.

## Etap 2 — transfer (jeszcze niezaimplementowany)
- Osobne zatwierdzenie przed każdym eksportem.
- Bezpieczny kanał przesyłania z kontrolą uprawnień; bez tokenów GitHub w logach ani odpowiedziach narzędzi.
- Weryfikacja SHA-256 po eksporcie, lista wyeksportowanych plików i możliwość wycofania.
- Kontrola kodu przed instalacją; żadnych automatycznych restartów Home Assistanta.

## Ważne
Sam prywatny status repozytorium **nie gwarantuje**, że wszystkie pliki są bezpieczne do publikacji. Weryfikacja wymaga dodatkowej kontroli przed transferem.

Aktualny SHA-256 `custom_components/dashboard_reader/llm.py` w HA (2026-11-12): `e770bf5469da4f844097e10ac6eea8df63875acd37a5507ca22c6d4fe0bf1ff6`.
