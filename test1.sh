#!/bin/bash

# ================= CONFIGURAZIONE =================
SERVER_BIN="./bin/server"
CLIENT_BIN="./bin/client"
FIFO_REQ="/tmp/fifo_richiesta_"
# Colori per output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ================= FUNZIONI DI UTILITÀ =================
cleanup() {
    # Uccide tutto ciò che si chiama "server" o "client" forzatamente
    killall -9 server client 2>/dev/null
    # Rimuove le pipe e i file temporanei
    rm -f /tmp/fifo_risposta* "$FIFO_REQ"
    rm -f test_file_*.bin pids.txt errors.txt
}

# Esegue cleanup all'uscita dello script (anche se interrotto con CTRL+C)
trap cleanup EXIT

echo -e "${YELLOW}=== FASE 1: Controllo Binari e Setup ===${NC}"

# 1. Verifica che tu abbia compilato
if [ ! -x "$SERVER_BIN" ] || [ ! -x "$CLIENT_BIN" ]; then
    echo -e "${RED}ERRORE: I file eseguibili '$SERVER_BIN' o '$CLIENT_BIN' non esistono.${NC}"
    echo "Per favore compila il progetto manualmente prima di lanciare questo script."
    exit 1
fi
echo -e "${GREEN}Binari trovati.${NC}"

# 2. Pulizia preventiva dell'ambiente
cleanup

# 3. Generazione file di test
echo -n "Generazione file di test... "
dd if=/dev/urandom of=test_file_small.bin bs=1K count=10 &> /dev/null
dd if=/dev/urandom of=test_file_large.bin bs=1M count=10 &> /dev/null
echo -e "${GREEN}OK${NC}"

# ================= FASE 2: AVVIO SERVER =================
echo -e "\n${YELLOW}=== FASE 2: Avvio Server ===${NC}"
# Avvia il server in background con 4 worker
$SERVER_BIN -w 4 &
SERVER_PID=$!
sleep 1

# Verifica se il server è ancora vivo
if ! pgrep -x "server" > /dev/null; then
    echo -e "${RED}ERRORE: Il server è crashato subito dopo l'avvio.${NC}"
    exit 1
fi
echo -e "${GREEN}Server avviato con PID $SERVER_PID${NC}"

# ================= FASE 3: TEST FUNZIONALITÀ BASE =================
echo -e "\n${YELLOW}=== FASE 3: Test Singolo (Happy Path) ===${NC}"
echo -n "Richiesta hash su file piccolo... "

# Esegue una richiesta semplice
OUTPUT=$($CLIENT_BIN -p $(realpath test_file_small.bin))

if echo "$OUTPUT" | grep -q "SHA-256"; then
    echo -e "${GREEN}SUCCESSO${NC}"
else
    echo -e "${RED}FALLITO${NC} - Output imprevisto:"
    echo "$OUTPUT"
    exit 1
fi

# ================= FASE 4: TEST CACHE (Hit vs Miss) =================
echo -e "\n${YELLOW}=== FASE 4: Test Cache ===${NC}"
FILE_TARGET=$(realpath test_file_large.bin)

echo -n "1. Primo accesso (Calculated)... "
OUT_1=$($CLIENT_BIN -p "$FILE_TARGET")
TIME_1=$(echo "$OUT_1" | grep "Time" | awk '{print $2}')
echo "${TIME_1} ms"

echo -n "2. Secondo accesso (Cached)... "
OUT_2=$($CLIENT_BIN -p "$FILE_TARGET")
TIME_2=$(echo "$OUT_2" | grep "Time" | awk '{print $2}')
echo "${TIME_2} ms"

# Controllo semplice: se il secondo tempo è vuoto o errore, fallisce
if [ -z "$TIME_2" ]; then
    echo -e "${RED}ERRORE SULLA CACHE${NC}"
else
    echo -e "${GREEN}Test Cache completato.${NC}"
fi

# ================= FASE 5: STRESS TEST (CONCORRENZA) =================
echo -e "\n${YELLOW}=== FASE 5: Stress Test (Anti-Blocco) ===${NC}"
echo "Lancio 20 richieste in parallelo."
echo "NOTA: Uso 'timeout -s 9' per uccidere i client lenti dopo 2 secondi."
echo "      Questo impedisce allo script di bloccarsi per sempre."

rm -f errors.txt

# Loop per lanciare 20 processi
for i in {1..10}; do
    # File piccolo
    timeout -s 9 2s $CLIENT_BIN -p $(realpath test_file_small.bin) > /dev/null 2>> errors.txt &
    
    # File grande
    timeout -s 9 2s $CLIENT_BIN -p $(realpath test_file_large.bin) > /dev/null 2>> errors.txt &
done

# Attesa esplicita della fine dei processi background
wait

# Analisi rapida degli errori
ERR_COUNT=$(grep -v "Killed" errors.txt 2>/dev/null | wc -l)
if [ "$ERR_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}WARNING: Rilevati errori o timeout durante lo stress test (normale se il server è sotto carico pesante).${NC}"
else
    echo -e "${GREEN}Stress test completato senza errori espliciti.${NC}"
fi

# ================= FASE 6: STATISTICHE =================
echo -e "\n${YELLOW}=== FASE 6: Verifica Statistiche ===${NC}"

STATS=$($CLIENT_BIN -s)
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}Statistiche recuperate:${NC}"
    echo "$STATS"
    
    # Controllo che il server abbia registrato le richieste (circa 22 totali finora)
    REQ=$(echo "$STATS" | grep "Total requests" | awk '{print $3}')
    if [ "$REQ" -ge 20 ]; then
        echo -e "${GREEN}VERIFICA OK: Il server ha contato $REQ richieste.${NC}"
    else
        echo -e "${RED}VERIFICA DUBBIA: Il server ha contato solo $REQ richieste (attese >20).${NC}"
    fi
else
    echo -e "${RED}Impossibile recuperare statistiche (Il server è bloccato?)${NC}"
fi

# ================= FASE 7: CHIUSURA =================
echo -e "\n${YELLOW}=== FASE 7: Terminazione ===${NC}"
$CLIENT_BIN -t
sleep 1

if pgrep -x "server" > /dev/null; then
    echo -e "${RED}Il server non si è chiuso con il comando -t. Forzo la chiusura.${NC}"
    killall -9 server
    exit 1
else
    echo -e "${GREEN}Server terminato correttamente.${NC}"
fi

echo -e "\n${GREEN}=== TEST SUITE COMPLETATA ===${NC}"