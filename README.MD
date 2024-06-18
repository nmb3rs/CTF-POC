### Heap Challenges:

1. **0xLaugh 2023** - [PWN/pwn1](https://github.com/Numb3rsProprety/CTF-POC/blob/main/0xLaugh2023/PWN/pwn1/exploit.py)
   - Description: Tcache poisoning.
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/blob/main/0xLaugh2023/PWN/pwn1/exploit.py)

2. **1337CTF 2023** - [PWN/Maltigriti](https://github.com/Numb3rsProprety/CTF-POC/blob/main/1337CTF2023/PWN/Maltigriti/exploit.py)
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/blob/main/1337CTF2023/PWN/Maltigriti/exploit.py)

3. **FCSC 2023** - [PWN/Robot](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2023/PWN/Robot/exploit.py)
   - Description: Exploit UAF to leak PIE and then to rewrite heap structures to call an arbitrary function. 
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2023/PWN/Robot/exploit.py)

4. **FCSC 2024** - [PWN/Cheapolata](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2024/PWN/Cheapolata/exploit.py)
   - Description: Exploit double free to overwrite local `__free_hook`
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2024/PWN/Cheapolata/exploit.py)
   - Writeup: https://numb3rs.re/writeup/fcsc2024_cheapolata/

5. **FCSC 2024** - [PWN/BookWriter](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2024/PWN/BookWriter/exploit.py)
   - Description: Exploit int overflow to have an out of bound.
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2024/PWN/BookWriter/exploit.py)

6. **FCSC 2024** - [PWN/BookWriterEasy](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2024/PWN/BookWriterEasy/exploit.py)
   - Description: Easier version of Book Writer. Exploit int overflow to have an out of bound.
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2024/PWN/BookWriterEasy/exploit.py)


### Stack Challenges:

1. **404CTF 2023** - [PWN/Alchimiste](https://github.com/Numb3rsProprety/CTF-POC/blob/main/404CTF2023/PWN/Alchimiste/exploit.py)
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/blob/main/404CTF2023/PWN/Alchimiste/exploit.py)

2. **AmateursCTF 2024** - [PWN/RNTK](https://github.com/Numb3rsProprety/CTF-POC/blob/main/AmateursCTF2024/PWN/RNTK/exploit.py)
   - Description: Exploit timebased canary and use overflow to overwrite return address.
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/blob/main/AmateursCTF2024/PWN/RNTK/exploit.py)

3. **FCSC 2023** - [PWN/Pterodactyle](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2023/PWN/Pterodactyle/exploit.py)
   - Description: Exploit overflow to overwrite longjmp structure.
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2023/PWN/Pterodactyle/exploit.py)

4. **GccCTF 2024** - [PWN/babybof](https://github.com/Numb3rsProprety/CTF-POC/blob/main/GccCTF2024/PWN/babybof/exploit.py)
   - Description: Exploit overflow in a SafeStack to overwrite tls.
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/blob/main/GccCTF2024/PWN/babybof/exploit.py)

5. **WolvCTF 2024** - [PWN/DeepString](https://github.com/Numb3rsProprety/CTF-POC/tree/main/wolvCTF2024/PWN/DeepString/exploit.py)
   - Description: Exploit OOB to call arbitrary function
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/tree/main/wolvCTF2024/PWN/DeepString/exploit.py)

6. **WolvCTF 2024** - [PWN/Byteover](https://github.com/Numb3rsProprety/CTF-POC/tree/main/wolvCTF2024/PWN/byteover/exploit.py)
   - Description: Exploit Off By One on the stack.
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/tree/main/wolvCTF2024/PWN/byteover/exploit.py)

7. **FCSC 2024** - [PWN/Note a bug 2](https://github.com/Numb3rsProprety/CTF-POC/tree/main/FCSC2024/PWN/Note%20a%20Bug%202/)
   - Description: Exploit overflow to execute a ROP that calls memprotect to then execute a shellcode
   - Exploit Script: [Note A Bug 2](https://github.com/Numb3rsProprety/CTF-POC/tree/main/FCSC2024/PWN/Note%20a%20Bug%202/)

8. **FCSC 2024** - [PWN/Note a Bug 3](https://github.com/Numb3rsProprety/CTF-POC/tree/main/FCSC2024/PWN/Note%20a%20bug%203/)
   - Description: Exploit overflow to leak libc to execute a ROP that calls memprotect to then execute a shellcode
   - Exploit Script: [Note A Bug 3](https://github.com/Numb3rsProprety/CTF-POC/tree/main/FCSC2024/PWN/Note%20a%20bug%203/)


### Format String Challenges:

1. **1337CTF 2023** - [PWN/floormats](https://github.com/Numb3rsProprety/CTF-POC/blob/main/1337CTF2023/PWN/floormats/exploit.py)
   - Description: Leak flag via format string.
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/blob/main/1337CTF2023/PWN/floormats/exploit.py)

### VM Challenges:

1. **FCSC 2023** - [PWN/MayTheFifth](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2023/PWN/MayTheFifth/exploit.py)
   - Description: Leak environ variable via OOB in a dynamic zForth compiler.
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2023/PWN/MayTheFifth/exploit.py)

2. **FCSC 2023** - [PWN/MayTheForth](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2023/PWN/MayTheForth/exploit.py)
   - Description: Pop a shell in a dynamic zForth compiler via PEEK and POKE syscalls.
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2023/PWN/MayTheForth/exploit.py)

3. **PWNME 2023** - [PWN/Chip8](https://github.com/Numb3rsProprety/CTF-POC/blob/main/PWNME2023/PWN/Chip8/exploit.py)
   - Description: Exploitation of an OOB in a register of the VM.
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2023/PWN/MayTheForth/exploit.py)

### Special Challenges:

1. **FCSC 2024** - [PWN/ZarbyWrite](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2024/PWN/ZarbyWrite/exploit.py)
   - Description: Exploit arbitrary write to overwrite exit routine
   - Exploit Script: [exploit.py](https://github.com/Numb3rsProprety/CTF-POC/blob/main/FCSC2024/PWN/ZarbyWrite/exploit.py)

