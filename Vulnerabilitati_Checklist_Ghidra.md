# Checklist vulnerabilități — ce caut în Ghidra

Ghid rapid: pentru fiecare tip de vulnerabilitate, ce tipar de cod decompilat
recunosc în Ghidra, cu un exemplu de pseudocod (stil Ghidra) care arată exact
tiparul, și la ce template/metodă trec mai departe.

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

```c
void vulnerable(void) {
    char local_2c[36];          // <-- buffer de 36 octeti
    puts("Insert your message:");
    gets(local_2c);              // <-- VULNERABIL: gets() nu verifica lungimea,
                                  //     pot scrie oricat de mult, dincolo de 36
}

void win(void) {                 // <-- 0x080491b6, NU e apelata nicaieri
    system("/bin/sh");
}
```

**Cum rezolv:** găsesc OFFSET-ul (cyclic/pattern search sau static din prolog),
apoi trimit `"A"*OFFSET + adresa_win` (32-bit, template `01_ret2win_x86.py`)
sau `"A"*OFFSET + ret_gadget + adresa_win` (64-bit, template `02_ret2win_x64.py`,
gadgetul de aliniere doar dacă e nevoie). Dacă nu există `win()`, trec la
ret2libc (vezi punctele 3-4 de mai jos despre leak, apoi template-urile
`03_ret2libc_x86_plt.py` / `04_ret2libc_x64_2etape.py`).

## 2. Integer overflow (semn)

- O variabilă `int` (nu `unsigned`) folosită ca și contor/scor, incrementată
  într-o buclă, cu o verificare de tipul `if (contor < 0)` sau
  `if (contor > ceva)` undeva în cod, dar fără limită de sus pe incrementare.
- Dacă pot scrie direct acea variabilă (printr-un buffer alăturat vulnerabil)
  → template `09_integer_overflow_contor.py`.

```c
void count_forever(void) {
    char  buf[16];
    int   contor = 0;            // <-- la ebp-0xc, langa buffer la ebp-0x1c

    puts("Let's count to the infinity");
    read(0, buf, 0x100);         // <-- VULNERABIL: pot scrie 0x7FFFFFFF peste `contor`
    contor = contor + 1;         // <-- 0x7FFFFFFF + 1 = 0x80000000 = NEGATIV (overflow de semn)
    if (contor < 0) {
        win();                    // <-- se declanseaza automat
    }
}
```

**Cum rezolv:** calculez offsetul până la variabila `contor` (nu până la
adresa de retur!), trimit `"A"*OFFSET + p32(0x7FFFFFFF)` ca să scriu direct
valoarea maximă pozitivă peste contor, apoi aștept ca programul să facă
singur incrementarea care cauzează overflow-ul de semn. Template:
`09_integer_overflow_contor.py`.

## 3. Format string LEAK (citire)

- Văd `printf(buffer)`, `fprintf(stdout, buffer)` sau `syslog(LOG_INFO, buffer)`
  unde `buffer` e EXACT ce am trimis eu, FĂRĂ un literal `"%s"` în jur (adică
  NU `printf("%s", buffer)`, ci direct `printf(buffer)`).
- Cel mai ușor de ratat — caut orice apel la o funcție din familia
  `printf`/`scanf` unde primul argument e o variabilă, nu un string literal.

```c
void show_message(void) {
    char buf[64];
    fgets(buf, 64, stdin);
    printf(buf);                 // <-- VULNERABIL: ar trebui sa fie printf("%s", buf)
                                  //     asa, pot trimite "%9$p" si citesc stiva
}
```

**Cum rezolv:** scanez pozițiile de argument trimițând `"AAAA%N$x"` (sau
folosesc scriptul `05_format_string_leak.py`, care scanează automat un
interval de poziții) până găsesc unde apare ceva relevant (adresă, canary,
sau direct text/flag). Dacă e flag răspândit pe mai multe poziții
consecutive, reconstruiesc octeții cu `struct.pack("<I", ...)` pe fiecare
valoare și le concatenez.

## 4. Format string WRITE (%n / %hn)

- Aceeași semnătură ca la punctul 3, dar contextul sugerează că pot SCRIE
  ceva persistent (un flag intern, o adresă de hook) — de obicei challenge-ul
  are un mesaj gen "acum verific flagul X" după ce trimit formatul.

```c
void (*hook)(void) = default_func;   // <-- pointer global catre o functie

void process(void) {
    char buf[128];
    read(0, buf, 128);
    printf(buf);                      // <-- VULNERABIL: pot folosi %hn ca sa scriu
                                       //     peste `hook`, suprascriindu-l cu win()
    hook();                           // <-- va sari la ce am scris eu
}
```

**Cum rezolv:** găsesc poziția (`POZ`) a argumentelor mele în format string
(trimit `"AAAA%N$x"` până recunosc `0x41414141`). Calculez cele două jumătăți
de 16 biți ale adresei țintă (`val_jos`, `val_sus`), aleg să scriu întâi
valoarea mai MICĂ (ca să nu trebuiască să "scad" contorul lui printf), și
construiesc payload-ul cu `%{pad}c%{POZ}$hn` de două ori. Template:
`06_format_string_write_hn.py`.

## 5. GOT overwrite / scriere arbitrară custom

- Un array global indexat de un input al meu, FĂRĂ validare de limite:
  `*(long *)(array_global + index * 8) = valoare_citita_de_la_mine;` — dacă
  `index` poate fi negativ sau foarte mare și nu e verificat, pot scrie
  oriunde în memorie, inclusiv în GOT.
- Verific și `checksec`: RELRO trebuie să fie Partial sau No (Full RELRO face
  GOT read-only).

```c
long talis[16];                        // <-- 0x4040a0, array global

void cast_spell(void) {
    int index;
    short value;
    printf(">> ");
    scanf("%d", &index);               // <-- NU verifica limitele!
    printf("Spell: ");
    read(0, &value, 2);
    *(short *)((char *)talis + index * 8) = value;  // <-- VULNERABIL: scriere arbitrara
}
```

**Cum rezolv:** găsesc adresa array-ului de bază (`nm`/`objdump`) și adresa
GOT țintă (`objdump -R | grep nume_functie`), calculez
`index = (TARGET - BASE) // ELEMENT_SIZE`, și trimit indexul + cei 2/8 octeți
noi la prompturile programului. Template: `07_got_overwrite_arbitrary_write.py`.

## 6. Shellcode pe stivă executabilă

- `checksec` arată `Stack: Executable` (NX dezactivat) SAU, în `vmmap` (din
  GEF), stiva are permisiuni `rwx`.
- Codul în sine arată ca un buffer overflow banal — diferența e doar în
  protecții, nu în cod.

```c
void vulnerable(void) {
    char buf[64];                     // <-- checksec: Stack: Executable (NX off)
    read(0, buf, 500);                // <-- VULNERABIL: pot pune shellcode AICI
                                       //     si sa sar direct in el (fara nevoie
                                       //     de win()/libc)
}
```

**Cum rezolv:** generez shellcode cu `shellcraft.sh()` din pwntools, pun un
"covor" de NOP-uri înainte de el (ca să nu trebuiască să sar EXACT la primul
octet), calculez `OFFSET`, și sar fie la o adresă de stivă cunoscută (dacă nu
e ASLR), fie la una obținută dintr-un leak separat. Template:
`08_shellcode_stiva_executabila.py`.

## 7. Leak prin SIGSEGV + signal handler

- Văd `signal(SIGSEGV, nume_handler)` sau `sigaction(...)` undeva la începutul
  lui `main()`. Funcția handler tipărește ceva (de obicei o adresă) înainte
  să continue/reapeleze funcția originală.

```c
void sig_handler(int sig) {
    printf("Here's your gift: %p\n", win);   // <-- LEAK: adresa reala a lui win()
    make_a_wish();                            // <-- reapeleaza functia vulnerabila
}

int main(void) {
    signal(SIGSEGV, sig_handler);             // <-- la primul crash, sare aici
    make_a_wish();
}

void make_a_wish(void) {
    char buf[128];
    gets(buf);                                 // <-- VULNERABIL: primul overflow
                                                //     (adresa invalida) provoaca
                                                //     SIGSEGV -> handler -> leak
}
```

**Cum rezolv:** fac un prim overflow "de test" (`"A"*OFFSET + "B"*8`) doar ca
să provoc crash-ul controlat, citesc din răspunsul serverului adresa afișată
de handler (`int(linia, 16)`), apoi fac un AL DOILEA overflow, de data asta
cu adresa reală a lui `win()` ca adresă de retur — vezi exemplul complet la
`signal_to_nowhere` în ghidul de linie-cu-linie.

## 8. Leak de canary / PIE prin format string

- `checksec` arată `Canary: Yes` și/sau `PIE: Enabled`, ȘI există undeva un
  `printf(buffer)` vulnerabil (vezi punctul 3) prin care pot scoate valoarea
  canary-ului sau o adresă din binar înainte de orice overflow real.

```c
void add_summery(void) {
    char fmt[32];
    read(0, fmt, 32);
    printf(fmt);                      // <-- VULNERABIL: trimit "%9$p" si citesc
                                       //     canary-ul de pe stiva INAINTE sa fac
                                       //     overflow-ul real (care altfel ar crapa
                                       //     din cauza canary-ului modificat)
}
```

**Cum rezolv:** trimit `"%9$p"` (sau poziția găsită prin scanare, vezi
punctul 3) ca sa citesc canary-ul/adresa ÎNAINTE de overflow-ul real, verific
că nu conține octeți de whitespace (altfel `scanf`/`gets` l-ar tăia), apoi
construiesc payload-ul final `"A"*OFFSET + p64(canary) + p64(junk_rbp) +
adresa_tinta` — canary-ul trebuie pus EXACT la poziția lui originală, ca
verificarea internă să treacă.

## 9. PRNG previzibil (srand/rand)

- Văd `srand(seed)` unde `seed`-ul e CITIT DE LA MINE (nu `srand(time(NULL))`),
  urmat de `rand()` folosit pentru decizii din joc (zaruri, carte, număr
  norocos).
- Dacă seed-ul vine de la `time(NULL)` în schimb, NU mai e previzibil direct
  din partea mea — verific dacă pot totuși sincroniza timpul sau dacă există
  altă slăbiciune.

```c
void play_round(void) {
    int seed, roll;
    printf("Choose your lucky number\n");
    scanf("%d", &seed);
    srand(seed);                       // <-- VULNERABIL: seed-ul vine de la mine!
    roll = rand() % 60 + 1;            // <-- pot reproduce local acelasi rezultat
                                        //     (vezi 10_bruteforce_prng_ctypes.py)
}
```

**Cum rezolv:** încarc `libc.so.6` în Python cu `ctypes.CDLL`, caut local (fără
conexiune la server) un `seed` pentru care `srand(seed)` + `rand() % MOD`
dă mereu rezultatul maxim dorit, apoi trimit acel seed de câte ori e nevoie
la fiecare rundă a jocului. Template: `10_bruteforce_prng_ctypes.py`.

## 10. Apeluri înlănțuite fără argumente (ret2func repetat)

- O funcție fără parametri care doar tipărește ceva și face `ret`, apelabilă
  repetat prin suprascrierea adresei de retur de mai multe ori la rând (ca
  la `marathon`) — utilă când vreau să "storc" informație caracter-cu-caracter
  dintr-o funcție care normal se apelează o singură dată.

```c
void milestone_prize(void) {
    static int idx = 0;
    printf("Km %d: %c\n", idx, password[idx]);  // <-- tipareste UN caracter per apel
    idx++;
}                                                  // <-- apoi face "ret" normal

void marathon(void) {
    char buf[40];
    gets(buf);               // <-- VULNERABIL: suprascriu adresa de retur de 18 ori
                              //     cu milestone_prize, apoi o data cu menu()
}
```

**Cum rezolv:** calculez `NUM_CHARS` (câte caractere are ce vreau să extrag,
de obicei vizibil dintr-un apel `generate_X(N)` în decompilare), construiesc
payload-ul `"A"*OFFSET + p32(FUNCTIE)*NUM_CHARS + p32(MENU)` — adresa funcției
repetată de N ori, urmată de adresa unde vreau să revin ca programul să nu
crape — apoi citesc liniile de output și reconstruiesc rezultatul în ordine
(cu regex, ca la `marathon`).

## 11. Suprascriere a cheii/stării unui algoritm (XOR, criptare simplă)

- O variabilă globală sau statică folosită ca cheie într-un `for` cu XOR
  (`buf[i] ^= cheie[i % N]`), aflată lângă un buffer vulnerabil la overflow —
  pot suprascrie cheia direct, înainte ca programul s-o folosească la
  decriptare.

```c
char key[8] = "s3cr3tk"; // <-- cheia XOR, langa buffer-ul vulnerabil pe stiva

void encrypt_msg(void) {
    char buf[64];
    gets(buf);                         // <-- VULNERABIL: pot suprascrie `key`
                                        //     (daca e pe stiva, imediat dupa buf)
    for (int i = 0; i < 64; i++)
        buf[i] ^= key[i % 8];          // <-- decriptarea foloseste cheia MEA
}
```

**Cum rezolv:** calculez offsetul până la variabila cheii (nu până la adresa
de retur) și scriu direct peste ea cu o valoare cunoscută de mine (de ex.
toți octeții `0x00` sau o cheie simplă pe care o știu dinainte), astfel încât
decriptarea ulterioară din program să folosească cheia MEA, nu cea originală
— utilă chiar dacă nu pot controla adresa de retur deloc.

## 12. Condiție ascunsă în spatele unui "milestone"/contor de reușite

- `if (contor_global >= PRAG) { permite_overflow_real(); }` — trebuie să
  "antrenez" programul cu răspunsuri corecte repetate înainte ca overflow-ul
  propriu-zis să fie acceptat (ca la `model_activ`).

```c
int milestone = 0;                      // <-- global, numara raspunsuri corecte

void round(void) {
    char buf[32];
    printf("Enter your lucky number\n");
    read(0, buf, (milestone >= 9) ? 48 : 32);  // <-- VULNERABIL doar dupa 9 reusite!
    if (check_answer(buf)) milestone++;
}
```

**Cum rezolv:** trimit payload-ul "valid" (care trece verificarea internă) de
atâtea ori cât e nevoie ca să ating pragul (determinat empiric sau găsit în
decompilare), apoi, DUPĂ ce pragul e atins, trimit un payload mai lung care
ajunge efectiv la adresa de retur — ca la `model_activ`, unde primele 9
trimiteri "antrenează" contorul, iar a 10-a face overflow-ul real.

---

## Ce ar mai putea apărea (nu l-am întâlnit încă, dar e comun la laborator)

- **Use-after-free / double-free** — dacă challenge-ul face `malloc`/`free`
  manual și refolosește un pointer după `free()`. Recunosc după perechi
  `malloc`/`free` fără ca pointerul să fie resetat la `NULL`.

```c
char *p = malloc(64);
strcpy(p, "date secrete");
free(p);                   // <-- memoria e "eliberata", dar p inca "arata" acolo
...
strcpy(p, input_de_la_mine);  // <-- VULNERABIL: use-after-free, scriu in memorie
                               //     care ar putea fi deja realocata altceva
```

**Cum rezolv:** forțez programul să aloce din nou (`malloc`) ceva de aceeași
mărime DUPĂ `free()`, ca noua alocare să primească probabil exact aceeași
adresă (comportament tipic al alocatorului), apoi scriu date controlate de
mine prin acel nou obiect — efectiv suprascriu conținutul la care încă
"arată" vechiul pointer folosit mai departe de program.

- **Off-by-one** — overflow de UN SINGUR octet (de obicei suprascrie doar
  byte-ul cel mai puțin semnificativ al saved ebp/canary) — apare când o
  buclă folosește `<=` în loc de `<` la limita bufferului.

```c
char buf[32];
for (int i = 0; i <= 32; i++)   // <-- VULNERABIL: "<=" in loc de "<", scrie 33 octeti
    buf[i] = getchar();
```

**Cum rezolv:** trimit exact `OFFSET+1` octeți (un octet peste limita normală)
— de obicei suprascriu doar byte-ul cel mai puțin semnificativ al saved
ebp/canary, ceea ce poate fi suficient ca să-l fac să "pointeze" undeva util
(ex. o adresă apropiată pe stivă), fără să stric restul canary-ului dacă
acesta se termină deja în `0x00`.

- **Race condition / TOCTOU** — verifică o condiție, apoi o folosește mai
  târziu, lăsând o fereastră de timp exploatabilă — mai rar la laborator, dar
  posibil dacă văd `fork()`/thread-uri.

```c
if (access("file.txt", W_OK) == 0) {   // <-- verifica permisiunea ACUM
    sleep(1);                           // <-- fereastra de timp exploatabila
    fopen("file.txt", "w");             // <-- foloseste fisierul MAI TARZIU
}
```

**Cum rezolv:** rulez în paralel (alt thread/proces) o acțiune care schimbă
starea verificată (ex. înlocuiesc fișierul cu un symlink) exact în fereastra
dintre verificare și folosire — necesită de obicei un script separat care
"bombardează" cu încercări repetate, nu doar o singură trimitere.

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
