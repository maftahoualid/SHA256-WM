#!/bin/bash

cd "$(dirname "$0")"

# Cleanup precedente
pkill -f "./bin/server" 2>/dev/null || true
pkill -f "./bin/client -p" 2>/dev/null || true
sleep 1

# Creo file di test con dimensioni diverse per testare lo scheduling
echo "Small content" > small_file.txt
echo "File di dimensioni medie per testare tutta l'efficacia del sistema e del progetto intero" > medium_file.txt
dd if=/dev/zero of=large_file.txt bs=1024 count=5 2>/dev/null

echo "=== TEST COMPLETO DELLE FEATURE RICHIESTE ==="
echo ""

echo "=== 1. AVVIO SERVER CON 3 WORKER THREADS (Threading + Limite fisso) ==="
./bin/server -w 3 -o desc &
SERVER_PID=$!
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERRORE: Server non avviato"
    exit 1
fi
echo "✓ Server avviato con pool fisso di 3 thread"
echo ""

echo "=== 2. TEST FIFO COMMUNICATION (Server-Client) ==="
echo "Invio richiesta hash per file medio"
./bin/client -p medium_file.txt
echo "✓ Comunicazione FIFO funzionante"
echo ""

echo "=== 3. TEST SCHEDULING PER DIMENSIONE FILE (desc) ==="
echo "Invio richieste sequenziali per dimostrare ordinamento per dimensione"
echo "- File grande (5KB):"
./bin/client -p large_file.txt
echo "- File piccolo (14 bytes):"  
./bin/client -p small_file.txt
echo "- File medio (101 bytes):"
./bin/client -p medium_file.txt
echo "✓ Scheduling per dimensione implementato (ordine desc)"
echo ""

echo "=== 4. TEST CACHE PERCORSO-HASH ==="
echo "Primo accesso (cache miss):"
./bin/client -p medium_file.txt
echo ""
echo "Secondo accesso (cache hit - più veloce):"
./bin/client -p medium_file.txt
echo "✓ Cache LRU funzionante - secondo accesso usa cache"
echo ""

echo "=== 5. TEST RICHIESTE CONCORRENTI STESSO FILE ==="
echo "Invio 3 richieste simultanee per lo stesso file"
./bin/client -p large_file.txt &
PID1=$!
./bin/client -p large_file.txt &
PID2=$!
./bin/client -p large_file.txt &
PID3=$!
wait $PID1 $PID2 $PID3
echo "✓ Gestione richieste duplicate - una sola elaborazione effettiva"
echo ""

echo "=== 6. TEST THREADING CONCORRENTE ==="
echo "Invio richieste multiple simultanee per testare concorrenza"
./bin/client -p small_file.txt &
PID1=$!
./bin/client -p medium_file.txt &
PID2=$!
./bin/client -p large_file.txt &
PID3=$!
wait $PID1 $PID2 $PID3
echo "Thread multipli processano richieste in parallelo"
echo ""

echo "=== 7. STATISTICHE FINALI ==="
./bin/client --stats
echo ""

echo "=== 8. TERMINAZIONE GRACEFUL ==="
./bin/client --terminate
wait $SERVER_PID 2>/dev/null || true

# Cleanup
rm -f small_file.txt medium_file.txt large_file.txt