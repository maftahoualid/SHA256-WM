ISTRUAZIONI PER IL PROFESSORE - Bozza Denise VR471516

I comandi per eseguire il tutto sono:

  mkdir build && cd build
  cmake ..
  make


Gli eseguibili saranno in bin/:

- bin/server
- bin/client
- bin/test_suite


Altrimenti può usare lo script build.sh che fara tutti i comandi sopra-elencati. La scelta ovviamente va a sua discrezione

  ./build.sh


Invece per quanto riguarda il testing è presente nella cartella uno script test.sh che esegue tutte le funzionalità principali del progetto, volendo ovviamente, come scritto nella documentazione, è possibile eseguire i comandi anche manualmente.

  ./test.sh
