# Checklist vulnerabilități — ce caut în Ghidra

Ghid rapid: pentru fiecare tip de vulnerabilitate, ce tipar de cod decompilat
recunosc în Ghidra și la ce template/metodă trec mai departe.

## 1. Buffer overflow clasic (ret2win / ret2libc)

- Văd `gets(buffer)`, `scanf("%s", buffer)`, `fgets(buffer, 999, stdin)` cu un
  număr mult mai mare decât mărimea reală a bufferului, sau
  `read(0, buffer, 0x500)` pe un buffer de 0x40.
- Verific: mărimea bufferului din decompilare (`local_XX` / `auStack_XX`) vs.
  câți octeți poate citi funcția — dacă citirea permite mai mult decât
  bufferul, e overflow.
- Caut în Symbol Tree o funcție gen `win`/`flag`/`backdoor`/`shell` nefolosită
  nicăieri → **ret2win**. Dacă nu există → **ret2libc** (verific dacă
  `system`/`puts` apar deja importate).

## 2. Integer overflow (semn)

- O variabilă `int` (nu `unsigned`) folosită ca și contor/scor, incrementată
  într-o buclă, cu o verificare de tipul `if (contor < 0)` sau
  `if (contor > ceva)` undeva în cod, dar fără limită de sus pe incrementare.
- Dacă pot scrie direct acea variabilă (printr-un buffer alăturat vulnerabil)
  → template `09_integer_overflow_contor.py`.

## 3. Format string LEAK (citire)

- Văd `printf(buffer)`, `fprintf(stdout, buffer)` sau `syslog(LOG_INFO, buffer)`
  unde `buffer` e EXACT ce am trimis eu, FĂRĂ un literal `"%s"` în jur (adică
  NU `printf("%s", buffer)`, ci direct `printf(buffer)`).
- Cel mai ușor de ratat — caut orice apel la o funcție din familia
  `printf`/`scanf` unde primul argument e o variabilă, nu un string literal.

## 4. Format string WRITE (%n / %hn)

- Aceeași semnătură ca la punctul 3, dar contextul sugerează că pot SCRIE
  ceva persistent (un flag intern, o adresă de hook) — de obicei challenge-ul
  are un mesaj gen "acum verific flagul X" după ce trimit formatul.

## 5. GOT overwrite / scriere arbitrară custom

- Un array global indexat de un input al meu, FĂRĂ validare de limite:
  `*(long *)(array_global + index * 8) = valoare_citita_de_la_mine;` — dacă
  `index` poate fi negativ sau foarte mare și nu e verificat, pot scrie
  oriunde în memorie, inclusiv în GOT.
- Verific și `checksec`: RELRO trebuie să fie Partial sau No (Full RELRO face
  GOT read-only).

## 6. Shellcode pe stivă executabilă

- `checksec` arată `Stack: Executable` (NX dezactivat) SAU, în `vmmap` (din
  GEF), stiva are permisiuni `rwx`.
- Codul în sine arată ca un buffer overflow banal — diferența e doar în
  protecții, nu în cod.

## 7. Leak prin SIGSEGV + signal handler

- Văd `signal(SIGSEGV, nume_handler)` sau `sigaction(...)` undeva la începutul
  lui `main()`. Funcția handler tipărește ceva (de obicei o adresă) înainte
  să continue/reapeleze funcția originală.

## 8. Leak de canary / PIE prin format string

- `checksec` arată `Canary: Yes` și/sau `PIE: Enabled`, ȘI există undeva un
  `printf(buffer)` vulnerabil (vezi punctul 3) prin care pot scoate valoarea
  canary-ului sau o adresă din binar înainte de orice overflow real.

## 9. PRNG previzibil (srand/rand)

- Văd `srand(seed)` unde `seed`-ul e CITIT DE LA MINE (nu `srand(time(NULL))`),
  urmat de `rand()` folosit pentru decizii din joc (zaruri, carte, număr
  norocos).
- Dacă seed-ul vine de la `time(NULL)` în schimb, NU mai e previzibil direct
  din partea mea — verific dacă pot totuși sincroniza timpul sau dacă există
  altă slăbiciune.

## 10. Apeluri înlănțuite fără argumente (ret2func repetat)

- O funcție fără parametri care doar tipărește ceva și face `ret`, apelabilă
  repetat prin suprascrierea adresei de retur de mai multe ori la rând (ca
  la `marathon`) — utilă când vreau să "storc" informație caracter-cu-caracter
  dintr-o funcție care normal se apelează o singură dată.

## 11. Suprascriere a cheii/stării unui algoritm (XOR, criptare simplă)

- O variabilă globală sau statică folosită ca cheie într-un `for` cu XOR
  (`buf[i] ^= cheie[i % N]`), aflată lângă un buffer vulnerabil la overflow —
  pot suprascrie cheia direct, înainte ca programul s-o folosească la
  decriptare.

## 12. Condiție ascunsă în spatele unui "milestone"/contor de reușite

- `if (contor_global >= PRAG) { permite_overflow_real(); }` — trebuie să
  "antrenez" programul cu răspunsuri corecte repetate înainte ca overflow-ul
  propriu-zis să fie acceptat (ca la `model_activ`).

---

## Ce ar mai putea apărea (nu l-am întâlnit încă, dar e comun la laborator)

- **Use-after-free / double-free** — dacă challenge-ul face `malloc`/`free`
  manual și refolosește un pointer după `free()`. Recunosc după perechi
  `malloc`/`free` fără ca pointerul să fie resetat la `NULL`.
- **Off-by-one** — overflow de UN SINGUR octet (de obicei suprascrie doar
  byte-ul cel mai puțin semnificativ al saved ebp/canary) — apare când o
  buclă folosește `<=` în loc de `<` la limita bufferului.
- **Race condition / TOCTOU** — verifică o condiție, apoi o folosește mai
  târziu, lăsând o fereastră de timp exploatabilă — mai rar la laborator, dar
  posibil dacă văd `fork()`/thread-uri.

---

## Primul reflex când deschid un binar nou în Ghidra

1. `checksec ./binar` înainte de orice, ca să știu ce protecții am de bătut.
2. Symbol Tree → caut funcții cu nume suspect (`win`, `flag`, `backdoor`,
   `secret`, `debug`) nefolosite nicăieri.
3. În `main()` sau meniul principal, urmăresc ce funcție citește input și
   cum îl citește (`gets`/`scanf`/`read`/`fgets`).
4. Mă uit dacă există vreun `printf`/`fprintf` fără `"%s"` explicit.
5. Verific dacă există `srand`/`rand`, `malloc`/`free`, sau array-uri indexate
   de input-ul meu fără validare.
