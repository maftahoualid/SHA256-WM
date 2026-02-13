#!/bin/bash

# Interrompi lo script immediatamente se un comando fallisce
set -e

# Definiamo i colori per l'output (stile "Senior")
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
RESET='\033[0m'

# Funzione per gestire gli errori
handle_error() {
    echo -e "${RED}[BUILD][ERRORE] La compilazione è fallita.${RESET}"
    exit 1
}

# Imposta la funzione handle_error in caso di fallimento
trap 'handle_error' ERR

echo -e "${YELLOW}[BUILD] Pulizia configurazioni precedenti...${RESET}"
# Rimuove la cache per essere sicuri che rilevi i nuovi file .h e .c
rm -f build/CMakeCache.txt

echo -e "${YELLOW}[BUILD] Creazione directory build...${RESET}"
mkdir -p build
cd build

echo -e "${YELLOW}[BUILD] Configurazione con CMake...${RESET}"
# Manteniamo --log-level=ERROR per non sporcare il terminale
cmake .. --log-level=ERROR

echo -e "${YELLOW}[BUILD] Compilazione del progetto...${RESET}"
make

echo -e ""
echo -e "${GREEN}[BUILD] SUCCESSO! Tutto compilato correttamente.${RESET}"
echo -e "${GREEN}[INFO]  Gli eseguibili sono pronti in ./bin/${RESET}"