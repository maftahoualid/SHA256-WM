#!/bin/bash

# ==============================================================================
# CONFIGURAZIONE
# ==============================================================================
SERVER_BIN="./bin/server"
CLIENT_BIN="./bin/client"
TEST_DIR="test_data"
SERVER_FIFO="/tmp/hash_server"

# Colori per output dello script
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ==============================================================================
# FUNZIONI DI UTILITÀ
# ==============================================================================

print_header() {
    echo -e "\n${BLUE}=================================================${NC}"
    echo -e "${BLUE}>>> $1 ${NC}"
    echo -e "${BLUE}=================================================${NC}"
}

cleanup() {
    echo -e "${YELLOW}[INFO] Pulizia ambiente in corso...${NC}"
    pkill -f "$SERVER_BIN" 2>/dev/null || true
    rm -rf $TEST_DIR
    rm -f /tmp/hash_client_*
    rm -f $SERVER_FIFO
}

trap cleanup EXIT

# ==============================================================================
# 1. PREPARAZIONE AMBIENTE
# ==============================================================================
print_header "1. PREPARAZIONE E GENERAZIONE FILE"

mkdir -p $TEST_DIR

echo -n "Generazione file di test..."
dd if=/dev/urandom of=$TEST_DIR/small.bin bs=1K count=1 2>/dev/null
dd if=/dev/urandom of=$TEST_DIR/medium.bin bs=1M count=1 2>/dev/null
dd if=/dev/urandom of=$TEST_DIR/large.bin bs=20M count=1 2>/dev/null
echo " Fatto."

echo -n "Calcolo hash di riferimento (ground truth)..."
REAL_HASH_SMALL=$(sha256sum $TEST_DIR/small.bin | awk '{print $1}')
REAL_HASH_MEDIUM=$(sha256sum $TEST_DIR/medium.bin | awk '{print $1}')
REAL_HASH_LARGE=$(sha256sum $TEST_DIR/large.bin | awk '{print $1}')
echo " Fatto."

# ==============================================================================
# 2. AVVIO SERVER
# ==============================================================================
print_header "2. AVVIO SERVER"

$SERVER_BIN -t 4 -o asc &
SERVER_PID=$!
sleep 2

if ps -p $SERVER_PID > /dev/null; then
   echo -e "${GREEN}✓ Server avviato correttamente (PID $SERVER_PID)${NC}"
else
   echo -e "${RED}ERRORE: Il server è crashato all'avvio.${NC}"
   exit 1
fi

# ==============================================================================
# 3. TEST CORRETTEZZA MATEMATICA (SHA-256)
# ==============================================================================
print_header "3. VERIFICA CORRETTEZZA HASH"

check_hash() {
    FILE=$1
    EXPECTED=$2
    NAME=$3
    
    # Esegue il client e PULISCE I CODICI COLORE con sed prima di cercare
    OUTPUT=$($CLIENT_BIN -p $(realpath $FILE) | sed 's/\x1b\[[0-9;]*m//g')
    
    # Ora la stringa è pulita: "[CLIENT][INFO] Hash: <valore>"
    # $1=[CLIENT][INFO], $2=Hash:, $3=<valore>
    RECEIVED=$(echo "$OUTPUT" | grep "Hash:" | awk '{print $3}')
    
    if [ "$RECEIVED" == "$EXPECTED" ]; then
        echo -e "${GREEN}✓ $NAME: OK${NC}"
    else
        echo -e "${RED}X $NAME: FALLITO${NC}"
        echo "  Atteso:   '$EXPECTED'"
        echo "  Ricevuto: '$RECEIVED'"
        exit 1
    fi
}

check_hash "$TEST_DIR/small.bin" "$REAL_HASH_SMALL" "File Piccolo"
check_hash "$TEST_DIR/medium.bin" "$REAL_HASH_MEDIUM" "File Medio"
check_hash "$TEST_DIR/large.bin" "$REAL_HASH_LARGE" "File Grande"

# ==============================================================================
# 4. TEST CACHE (Prestazioni e Hit Ratio)
# ==============================================================================
print_header "4. TEST SISTEMA DI CACHE"

echo "Richiedo nuovamente il file MEDIO (dovrebbe essere in cache)..."

START=$(date +%s%N)
$CLIENT_BIN -p $(realpath $TEST_DIR/medium.bin) > /dev/null
END=$(date +%s%N)
ELAPSED=$((($END - $START)/1000000))

echo "Tempo risposta cache: ${ELAPSED}ms"

# Recuperiamo stats pulendo i colori
STATS_OUTPUT=$($CLIENT_BIN -s | sed 's/\x1b\[[0-9;]*m//g')

# Stringa: "[CLIENT][INFO] Cache hits: <valore>"
# $1=[..], $2=Cache, $3=hits:, $4=<valore>
HITS=$(echo "$STATS_OUTPUT" | grep "Cache hits:" | awk '{print $4}')

if [ "$HITS" -ge "1" ]; then
    echo -e "${GREEN}✓ Cache Hit rilevato nelle statistiche ($HITS hits).${NC}"
else
    echo -e "${RED}X Cache Hit non incrementato! Il caching non funziona.${NC}"
    exit 1
fi

# ==============================================================================
# 5. TEST THUNDERING HERD
# ==============================================================================
print_header "5. TEST CONCORRENZA (Thundering Herd)"

# Creiamo un file NUOVO apposta per questo test. 
# Deve essere nuovo per costringere il server a calcolarlo (tempo > 0), 
# altrimenti userebbe la cache istantaneamente rendendo il test inutile.
echo "Generazione file dedicato 'thunder.bin' (20MB)..."
dd if=/dev/urandom of=$TEST_DIR/thunder.bin bs=20M count=1 2>/dev/null

echo "Lancio 5 richieste SIMULTANEE su file NUOVO."
echo "Il server dovrebbe calcolarlo UNA sola volta e servire gli altri 4 dalla cache."

STATS_BEFORE=$($CLIENT_BIN -s | sed 's/\x1b\[[0-9;]*m//g')
PROCESSED_BEFORE=$(echo "$STATS_BEFORE" | grep "Files processed:" | awk '{print $4}')

# Lanciamo i client in background e salviamo i PID
PIDS=()
for i in {1..5}; do
    $CLIENT_BIN -p $(realpath $TEST_DIR/thunder.bin) > /dev/null &
    PIDS+=($!) # Salva l'ultimo PID lanciato
done

# Aspettiamo specificamente ogni client
for pid in "${PIDS[@]}"; do
    wait $pid
done

STATS_AFTER=$($CLIENT_BIN -s | sed 's/\x1b\[[0-9;]*m//g')
PROCESSED_AFTER=$(echo "$STATS_AFTER" | grep "Files processed:" | awk '{print $4}')

DELTA=$((PROCESSED_AFTER - PROCESSED_BEFORE))
echo "File processati fisicamente durante questo test: $DELTA"

# Ci aspettiamo ESATTAMENTE 1 (il primo thread calcola, gli altri 4 aspettano la condition variable)
if [ "$DELTA" -eq "1" ]; then
    echo -e "${GREEN}✓ Thundering Herd gestito correttamente! (1 calcolo reale, 4 attese)${NC}"
else
    echo -e "${RED}X Fallito: Il server ha ricalcolato il file $DELTA volte.${NC}"
    exit 1
fi


# ==============================================================================
# 6. STRESS TEST
# ==============================================================================
print_header "6. STRESS TEST & THREAD POOL"
echo "Invio 10 richieste rapide..."
STRESS_PIDS=()
for i in {1..10}; do
    $CLIENT_BIN -p $(realpath $TEST_DIR/small.bin) > /dev/null &
    STRESS_PIDS+=($!)
done

# Attesa dei processi dello stress test
for pid in "${STRESS_PIDS[@]}"; do
    wait $pid
done

echo -e "${GREEN}✓ Stress test completato.${NC}"

# ==============================================================================
# 7. CHIUSURA
# ==============================================================================
print_header "7. TERMINAZIONE"
$CLIENT_BIN -c
sleep 1

if ps -p $SERVER_PID > /dev/null; then
   echo -e "${RED}X Il server non si è chiuso!${NC}"
   kill -9 $SERVER_PID
   exit 1
else
   echo -e "${GREEN}✓ Il server si è spento correttamente.${NC}"
fi

echo ""
echo -e "${GREEN}>>> TUTTI I TEST COMPLETATI CON SUCCESSO <<<${NC}"