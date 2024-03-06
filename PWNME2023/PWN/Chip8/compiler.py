from binascii import unhexlify
import sys
import re
from pwn import *


file = open(sys.argv[1], 'r').readlines()
todd_packer=make_packer('all')

rom_code = b""

"""

1. Instruction

2. Operand 1

3. Operand 2

"""


for line in file:
    operand1 = ""
    operand2 = ""
    operand3 = ""
    if line[0] == ";":
        continue
    if line.count(",") == 1 and line.count(" ") != 0:
        instruction, operand1, operand2 = re.split(' |,',line.strip())
        instruction = instruction.replace(" ", "")
        operand1 = operand1.replace(" ", "")
        operand2 = operand2.replace(" ", "")
    elif line.count(",") == 2 and line.count(" ") != 0:
        instruction, operand1, operand2, operand3 = re.split(' |,',line.strip())
        instruction = instruction.replace(" ", "")
        operand1 = operand1.replace(" ", "")
        operand2 = operand2.replace(" ", "")
        operand3 = operand3.replace(" ", "")
    elif line.count(" ") != 0:
        instruction, operand1 = re.split(' |,',line.strip())
        instruction = instruction.replace(" ", "")
        operand1 = operand1.replace(" ", "")
    elif line.count(" ")  == 0:
        instruction = line.strip().replace(" ", "")


    if instruction == "CLS":
        rom_code += b"\x00\xE0"
    elif instruction == "RET":
        rom_code += b"\x00\xEE"
    elif instruction == "LD" and "V" in operand1 :
        op1 = operand1.split("V")[1]
        temp_code = f"F{op1}65"
        rom_code += binascii.unhexlify(temp_code)
    elif instruction == "ADD" and operand1 == "I":
        op2 = operand2.split("V")[1]
        temp_code = f"F{op2}1E"
        rom_code += binascii.unhexlify(temp_code)
    elif instruction == "ADD" and "V" in operand1:
        op1 = operand1.split("V")[1]
        op2 = hex(int(operand2,0)).replace("0x","").rjust(2,"0")
        temp_code = f"7{op1}{op2}"
        rom_code += binascii.unhexlify(temp_code)
    elif instruction == "LD" and "V" not in operand2 and "I" == operand1:
        #Annn - LD I, addr
        op2 = hex(int(operand2, 0)).replace("0x", "")
        if len(op2) > 3:
            print("len too long for LD I, 0xyyy") 
        temp_code = f"A{op2}"
        rom_code += binascii.unhexlify(temp_code)
    elif instruction == "EXIT":
        rom_code += b"\x00\xFD"
    elif instruction == "DRW":
        op1 = operand1.split("V")[1]
        op2 = operand2.split("V")[1]
        op3 = operand3
        temp_code = f"D{op1}{op2}1"
        rom_code += binascii.unhexlify(temp_code)
    elif instruction == "XOR" and "V" in operand1 :
        op1 = operand1.split("V")[1]
        op2 = operand2.split("V")[1]
        temp_code = f"8{op1}{op2}3"
        rom_code += binascii.unhexlify(temp_code)
        

    print("[+] Instruction: %s" % instruction)

    if operand1 != "":
        print("[+] Operand 1: %s" % operand1)
    if operand2 != "":
        print("[+] Operand 2: %s" % operand2)   
    if operand3 != "":
        print("[+] Operand 3: %s" % operand3)    

with open("shellcode.rom", "wb") as code:
    code.write(rom_code)