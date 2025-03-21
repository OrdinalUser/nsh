# Špecifikácia projektu
Platform: Linux, x86_64
Programming language: C
Deadline: 9. cvicenie - tbd - TODO

# Special constraints
## Compiler options
- must compile with -Wall and 0 errors
## Forbidden library calls
- popen() and family => must use native syscalls instead of wrappers
- for additional features provide own implementations, no lib function calls or simple OS syscalls

# Features
- prompt format: 16:34 user17@student#
- must support at least 4 of these symbols: # ; < > | \
- must support taking input from stdin or sockets
  - my personal request = support ssh somehow
  - flag -p [port] will listen on socket and wait for connection
  - flag -u [path] will listen on a **local** socket
  - flag -c [port] remote server listening port
  - flag -h displays author info
  - flag -i sets either remote address or listening interface..

# Native commands
- help - vypis informacii ako pri flag -h
- quit - ukoncenie spojenia z ktoreho prikaz prisiel
- halt - ukoncenie celeho programu ??


# Flow
- flag -s (implicit) = shell acts as a server; waits for stdin or socket if other flags specified
- flag -c (explicit) = shell acts as an intermediary and

# Minimum capabilities
## Other
Spracovanie argumentov, spracovanie zadaneho vstupneho riadku, interne prikazy
- help
- halt
- quit
## Program management
Overenie cinnosti a spusutenie zadanych prikazov, presmerovanie
- fork
- exec
- wait
- pipe
- dup
- ... (thanks assignment for being specific)
## Sockets
sokety, spojenia // thanks for being specific yet again
- socket
- listen
- accept
- bind
- connect
- select
- read
- write

# Additional requirements
| Id | Points | Text |
|-|-|-|
| 1. | 2 | Non-interactive mode: Use files as scripts 
| 3. | 3 | nterný príkaz stat vypíše zoznam všetkých aktuálnych spojení na ktorých prijíma príkazy, prípadne aj všetky sokety na ktorých prijíma nové spojenia.
| 4. | 2 | Interný príkaz abort n ukončí zadané spojenie.
| 5. | 4 | Interné príkazy listen a close (s príslušnými argumentami) pre otvorenie a zatvorenie soketu pre prijímanie spojení.
| 7. | 2 | S prepínačom "-i" bude možné zadať aj IP adresu na ktorej bude program očakávať spojenia (nielen port).
| 8. | 3 | Prepínače "-i", "-p" bude možné zadať aj opakovane (viacnásobne pri
jednom spustení), teda spojenia sa budú napríklad prijímať na viacerých portoch, alebo viacerých lokálnych soketoch.