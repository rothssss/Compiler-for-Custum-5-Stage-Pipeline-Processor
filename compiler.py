#!/usr/bin/env python3
# compiler for 422 5 stage 16-bit processor
# takes .c or .asm files and outputs hex/binary
# usage: python3 compiler.py <file.c|file.asm> [hex|bin]

import re
import sys

# opcode table 
OPCODES = {
    "NOP":  0b0000,
    "ADD":  0b0001,
    "NOT":  0b0010,
    "AND":  0b0011,
    "XOR":  0b0100,
    "ADDI": 0b0101,
    "SR":   0b0110,
    "SL":   0b0111,
    "JAL":  0b1000,
    "RET":  0b1001,
    "BNEZ": 0b1010,
    "LD":   0b1011,
    "ST":   0b1100,
    "HALT": 0b1111,
}

# register name -> 3 bit number
REGS = {
    "R0": 0, "R1": 1, "R2": 2, "R3": 3,
    "R4": 4, "R5": 5, "R6": 6, "R7": 7,
    "SP": 6, "RA": 7,
}

# ---- assembler stuff ----

def parse_reg(text):
    text = text.strip().strip(",").upper()
    if text in REGS:
        return REGS[text]
    raise Exception(f"unknown register: {text}")

def parse_imm(text, bits, signed=True):
    # clean up the text and parse the number
    text = text.strip().strip(",").lstrip("#")
    if text.startswith("0x"):
        val = int(text, 16)
    else:
        val = int(text)

    # check if its in range
    if signed:
        low = -(1 << (bits - 1))
        high = (1 << (bits - 1)) - 1
    else:
        low = 0
        high = (1 << bits) - 1
    if val < low or val > high:
        raise Exception(f"immediate {val} out of range [{low}, {high}]")

    # mask to correct number of bits (handles negative -> twos complement)
    return val & ((1 << bits) - 1)

def assemble_one(mnemonic, ops):
    # encode a single instruction into 16 bits
    #   R-type (ADD/AND/XOR): [opcode:4][rd:3][rs:3][rt:3][000]
    #   NOT:                  [opcode:4][rd:3][rs:3][000000]
    #   ADDI:                 [opcode:4][rd:3][rs:3][imm:6]
    #   SR/SL:                [opcode:4][rd:3][rs:3][mod:1][shamt:5]
    #   JAL:                  [opcode:4][rd:3][imm:9]
    #   RET:                  [opcode:4][000][rs:3][000000]
    #   BNEZ:                 [opcode:4][rs:3][rt:3][offset:6]
    #   LD:                   [opcode:4][rs:3][offset:9]
    #   ST:                   [opcode:4][rs:3][rt:3][offset:6]

    op = OPCODES[mnemonic]
    word = op << 12

    if mnemonic in ("NOP", "HALT"):
        return word

    elif mnemonic in ("ADD", "AND", "XOR"):
        rd = parse_reg(ops[0])
        rs = parse_reg(ops[1])
        rt = parse_reg(ops[2])
        return word | (rd << 9) | (rs << 6) | (rt << 3)

    elif mnemonic == "NOT":
        rd = parse_reg(ops[0])
        rs = parse_reg(ops[1])
        return word | (rd << 9) | (rs << 6)

    elif mnemonic == "ADDI":
        rd = parse_reg(ops[0])
        rs = parse_reg(ops[1])
        imm = parse_imm(ops[2], 6)
        return word | (rd << 9) | (rs << 6) | imm

    elif mnemonic in ("SR", "SL"):
        rd = parse_reg(ops[0])
        rs = parse_reg(ops[1])
        mod = parse_imm(ops[2], 1, signed=False)  # 0=logical 1=arithmetic
        shamt = parse_imm(ops[3], 5, signed=False)
        return word | (rd << 9) | (rs << 6) | (mod << 5) | shamt

    elif mnemonic == "JAL":
        rd = parse_reg(ops[0])
        imm = parse_imm(ops[1], 9)
        return word | (rd << 9) | imm

    elif mnemonic == "RET":
        rs = parse_reg(ops[0])
        return word | (rs << 6)

    elif mnemonic == "BNEZ":
        rs = parse_reg(ops[0])
        rt = parse_reg(ops[1])
        offset = parse_imm(ops[2], 6)
        return word | (rs << 9) | (rt << 6) | offset

    elif mnemonic == "LD":
        rs = parse_reg(ops[0])
        offset = parse_imm(ops[1], 9)
        return word | (rs << 9) | offset

    elif mnemonic == "ST":
        rs = parse_reg(ops[0])
        rt = parse_reg(ops[1])
        offset = parse_imm(ops[2], 6)
        return word | (rs << 9) | (rt << 6) | offset

def assemble(source):
    lines = source.strip().splitlines()

    # first pass - find all the labels and their addresses
    labels = {}
    instructions = []
    addr = 0

    for raw in lines:
        # strip comments (after ; or //)
        line = raw.split(";")[0].split("//")[0].strip()
        if not line:
            continue

        # check for labels like "loop:"
        label_match = re.match(r"^(\w+):\s*(.*)", line)
        if label_match:
            labels[label_match.group(1).upper()] = addr
            line = label_match.group(2).strip()
            if not line:
                continue

        # split into tokens
        tokens = re.split(r"[,\s]+", line)
        tokens = [t for t in tokens if t]
        instructions.append((tokens[0].upper(), tokens[1:], addr))
        addr += 1

    # second pass - resolve labels and encode
    machine_code = []
    for mnemonic, ops, iaddr in instructions:
        resolved = []
        for o in ops:
            key = o.strip().strip(",").lstrip("#").upper()
            if key in labels:
                # for branches use PC-relative offset
                if mnemonic == "BNEZ":
                    resolved.append(str(labels[key] - (iaddr + 1)))
                else:
                    resolved.append(str(labels[key]))
            else:
                resolved.append(o)
        machine_code.append(assemble_one(mnemonic, resolved))

    return machine_code

# ---- C compiler  ----
# supports: int x = 5; assignment; if/else; while; +,-,*,&,^,~,<<,>>; halt;
# variables get mapped to R1-R5

# tokenizer regex 
TOKEN_REGEX = re.compile("|".join(f"(?P<{n}>{p})" for n, p in [
    ("NUM",     r"0x[0-9a-fA-F]+|\d+"),
    ("ID",      r"[a-zA-Z_]\w*"),
    ("LSHIFT",  r"<<"),
    ("RSHIFT",  r">>"),
    ("NEQ",     r"!="),
    ("EQ",      r"=="),
    ("ASSIGN",  r"="),
    ("PLUS",    r"\+"),
    ("MINUS",   r"-"),
    ("AMP",     r"&"),
    ("CARET",   r"\^"),
    ("TILDE",   r"~"),
    ("STAR",    r"\*"),
    ("LPAREN",  r"\("),
    ("RPAREN",  r"\)"),
    ("LBRACE",  r"\{"),
    ("RBRACE",  r"\}"),
    ("SEMI",    r";"),
    ("COMMA",   r","),
    ("SKIP",    r"[ \t]+"),
    ("NL",      r"\n"),
    ("COMMENT", r"//[^\n]*"),
    ("OTHER",   r"."),
]))

def tokenize(source):
    tokens = []
    line = 1
    for m in TOKEN_REGEX.finditer(source):
        kind = m.lastgroup
        val = m.group()
        if kind == "NL":
            line += 1
        elif kind in ("SKIP", "COMMENT"):
            pass
        elif kind == "OTHER":
            raise Exception(f"line {line}: unexpected character '{val}'")
        else:
            if kind == "NUM":
                val = int(val, 16) if val.startswith("0x") else int(val)
            tokens.append((kind, val, line))
    tokens.append(("EOF", None, line))
    return tokens

# parser - turns tokens into a simple tree made of tuples

class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos]

    def advance(self):
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def expect(self, kind):
        tok = self.advance()
        if tok[0] != kind:
            raise Exception(f"line {tok[2]}: expected {kind}, got {tok[0]}")
        return tok

    def parse_program(self):
        stmts = []
        while self.peek()[0] != "EOF":
            stmts.append(self.parse_statement())
        return stmts

    def parse_statement(self):
        tok = self.peek()
        if tok[0] == "ID" and tok[1] == "int":
            return self.parse_var_decl()
        elif tok[0] == "ID" and tok[1] == "if":
            return self.parse_if()
        elif tok[0] == "ID" and tok[1] == "while":
            return self.parse_while()
        elif tok[0] == "ID" and tok[1] == "halt":
            self.advance()
            self.expect("SEMI")
            return ("halt",)
        elif tok[0] == "ID":
            return self.parse_assign()
        else:
            raise Exception(f"line {tok[2]}: unexpected '{tok[1]}'")

    def parse_var_decl(self):
        self.advance()  # eat 'int'
        name = self.expect("ID")[1]
        init = None
        if self.peek()[0] == "ASSIGN":
            self.advance()
            init = self.parse_expr()
        self.expect("SEMI")
        return ("var", name, init)

    def parse_assign(self):
        name = self.advance()[1]
        self.expect("ASSIGN")
        expr = self.parse_expr()
        self.expect("SEMI")
        return ("assign", name, expr)

    def parse_if(self):
        self.advance()  # eat 'if'
        self.expect("LPAREN")
        cond = self.parse_condition()
        self.expect("RPAREN")
        self.expect("LBRACE")
        body = []
        while self.peek()[0] != "RBRACE":
            body.append(self.parse_statement())
        self.expect("RBRACE")
        # check for else
        else_body = []
        if self.peek()[0] == "ID" and self.peek()[1] == "else":
            self.advance()
            self.expect("LBRACE")
            while self.peek()[0] != "RBRACE":
                else_body.append(self.parse_statement())
            self.expect("RBRACE")
        return ("if", cond, body, else_body)

    def parse_while(self):
        self.advance()  # eat 'while'
        self.expect("LPAREN")
        cond = self.parse_condition()
        self.expect("RPAREN")
        self.expect("LBRACE")
        body = []
        while self.peek()[0] != "RBRACE":
            body.append(self.parse_statement())
        self.expect("RBRACE")
        return ("while", cond, body)

    def parse_condition(self):
        left = self.parse_expr()
        if self.peek()[0] == "NEQ":
            self.advance()
            return ("!=", left, self.parse_expr())
        elif self.peek()[0] == "EQ":
            self.advance()
            return ("==", left, self.parse_expr())
        # bare expression = "expr != 0"
        return ("!=", left, ("num", 0))

    # expression parsing - each level handles one precedence tier
    def parse_expr(self):
        return self.parse_bitwise()

    def parse_bitwise(self):
        node = self.parse_shift()
        while self.peek()[0] in ("AMP", "CARET"):
            tok = self.advance()
            op = "&" if tok[0] == "AMP" else "^"
            node = ("binop", op, node, self.parse_shift())
        return node

    def parse_shift(self):
        node = self.parse_add()
        while self.peek()[0] in ("LSHIFT", "RSHIFT"):
            tok = self.advance()
            op = "<<" if tok[0] == "LSHIFT" else ">>"
            node = ("binop", op, node, self.parse_add())
        return node

    def parse_add(self):
        node = self.parse_mul()
        while self.peek()[0] in ("PLUS", "MINUS"):
            tok = self.advance()
            op = "+" if tok[0] == "PLUS" else "-"
            node = ("binop", op, node, self.parse_mul())
        return node

    def parse_mul(self):
        node = self.parse_unary()
        while self.peek()[0] == "STAR":
            self.advance()
            node = ("binop", "*", node, self.parse_unary())
        return node

    def parse_unary(self):
        if self.peek()[0] == "TILDE":
            self.advance()
            return ("unary", "~", self.parse_primary())
        if self.peek()[0] == "MINUS":
            self.advance()
            return ("unary", "-", self.parse_primary())
        return self.parse_primary()

    def parse_primary(self):
        tok = self.peek()
        if tok[0] == "NUM":
            self.advance()
            return ("num", tok[1])
        elif tok[0] == "ID":
            self.advance()
            return ("var", tok[1])
        elif tok[0] == "LPAREN":
            self.advance()
            expr = self.parse_expr()
            self.expect("RPAREN")
            return expr
        raise Exception(f"line {tok[2]}: unexpected '{tok[1]}' in expression")


# code generator - walks the parse tree and spits out assembly
# maps C variables to registers R1-R5
class CodeGen:
    def __init__(self):
        self.lines = []          # output assembly lines
        self.var_map = {}        # variable name -> register
        self.next_reg = 1        # next register to assign
        self.label_count = 0

    def new_label(self):
        self.label_count += 1
        return f"L{self.label_count}"

    def emit(self, line):
        self.lines.append(line)

    def alloc(self, name):
        # assign a register to a new variable
        if name in self.var_map:
            return self.var_map[name]
        if self.next_reg > 5:
            raise Exception("out of registers! only 5 variables allowed (R1-R5)")
        reg = f"R{self.next_reg}"
        self.var_map[name] = reg
        self.next_reg += 1
        return reg

    def get(self, name):
        if name not in self.var_map:
            raise Exception(f"undefined variable: '{name}'")
        return self.var_map[name]

    def temp(self):
        # find an unused register for scratch work
        for i in range(5, 0, -1):
            if f"R{i}" not in self.var_map.values():
                return f"R{i}"
        raise Exception("no temp registers available")

    def compile(self, stmts):
        for s in stmts:
            self.compile_stmt(s)
        # make sure we end with HALT
        if not self.lines or "HALT" not in self.lines[-1].upper():
            self.emit("HALT")
        return "\n".join(self.lines)

    def compile_stmt(self, stmt):
        if stmt[0] == "var":
            reg = self.alloc(stmt[1])
            if stmt[2] is not None:
                self.compile_expr(stmt[2], reg)
            else:
                self.emit(f"ADD {reg}, R0, R0")  # init to 0
        elif stmt[0] == "assign":
            self.compile_expr(stmt[2], self.get(stmt[1]))
        elif stmt[0] == "if":
            self.compile_if(stmt)
        elif stmt[0] == "while":
            self.compile_while(stmt)
        elif stmt[0] == "halt":
            self.emit("HALT")

    def compile_expr(self, expr, dest):
        if expr[0] == "num":
            val = expr[1]
            if val == 0:
                self.emit(f"ADD {dest}, R0, R0")
            elif -32 <= val <= 31:
                # small enough to fit in ADDI immediate
                self.emit(f"ADDI {dest}, R0, {val}")
            else:
                self.build_constant(dest, val)

        elif expr[0] == "var":
            src = self.get(expr[1])
            if src != dest:
                self.emit(f"ADD {dest}, {src}, R0")  # copy

        elif expr[0] == "unary":
            self.compile_expr(expr[2], dest)
            if expr[1] == "~":
                self.emit(f"NOT {dest}, {dest}")
            elif expr[1] == "-":
                # negate = NOT + 1 (twos complement)
                self.emit(f"NOT {dest}, {dest}")
                self.emit(f"ADDI {dest}, {dest}, 1")

        elif expr[0] == "binop":
            self.compile_binop(expr[1], expr[2], expr[3], dest)

    def compile_binop(self, op, left, right, dest):
        # multiplication - no MUL instruction so we use shift+add
        if op == "*":
            if right[0] == "num":
                self.compile_expr(left, dest)
                self.compile_mul(dest, right[1])
            elif left[0] == "num":
                self.compile_expr(right, dest)
                self.compile_mul(dest, left[1])
            else:
                raise Exception("multiply needs at least one constant (e.g. x * 3)")
            return

        # add/sub small constant -> ADDI
        if op == "+" and right[0] == "num" and -32 <= right[1] <= 31:
            self.compile_expr(left, dest)
            self.emit(f"ADDI {dest}, {dest}, {right[1]}")
            return
        if op == "-" and right[0] == "num" and -31 <= right[1] <= 32:
            self.compile_expr(left, dest)
            self.emit(f"ADDI {dest}, {dest}, {-right[1]}")
            return

        # shift by constant
        if op in ("<<", ">>") and right[0] == "num":
            self.compile_expr(left, dest)
            instr = "SL" if op == "<<" else "SR"
            self.emit(f"{instr} {dest}, {dest}, 0, {right[1]}")
            return

        self.compile_expr(left, dest)
        t = self.temp()
        self.compile_expr(right, t)

        if op == "+":
            self.emit(f"ADD {dest}, {dest}, {t}")
        elif op == "-":
            # subtract = negate then add
            self.emit(f"NOT {t}, {t}")
            self.emit(f"ADDI {t}, {t}, 1")
            self.emit(f"ADD {dest}, {dest}, {t}")
        elif op == "&":
            self.emit(f"AND {dest}, {dest}, {t}")
        elif op == "^":
            self.emit(f"XOR {dest}, {dest}, {t}")

    def compile_mul(self, dest, n):
        # multiply dest register by constant n using shifts and adds
        if n == 0:
            self.emit(f"ADD {dest}, R0, R0")
            return
        if n == 1:
            return
        if n == 2:
            self.emit(f"SL {dest}, {dest}, 0, 1")
            return

        t = self.temp()
        self.emit(f"ADD {t}, {dest}, R0")  # save original

        # figure out which bits are set in n
        set_bits = []
        for i in range(16):
            if n & (1 << i):
                set_bits.append(i)

        first = True
        for bit in set_bits:
            if first:
                if bit != 0:
                    self.emit(f"SL {dest}, {t}, 0, {bit}")
                first = False
            else:
                prev = set_bits[set_bits.index(bit) - 1]
                self.emit(f"SL {t}, {t}, 0, {bit - prev}")
                self.emit(f"ADD {dest}, {dest}, {t}")

    def compile_if(self, stmt):
        cond = stmt[1]
        body = stmt[2]
        else_body = stmt[3]

        end_label = self.new_label()
        else_label = self.new_label() if else_body else None
        t = self.temp()
        self.eval_condition(cond, t)

        if cond[0] == "!=":
            body_label = self.new_label()
            self.emit(f"BNEZ {t}, R0, {body_label}")
            if else_body:
                self.emit(f"JAL R0, {else_label}")
            else:
                self.emit(f"JAL R0, {end_label}")
            self.emit(f"{body_label}:")
            for s in body:
                self.compile_stmt(s)
            if else_body:
                self.emit(f"JAL R0, {end_label}")
                self.emit(f"{else_label}:")
                for s in else_body:
                    self.compile_stmt(s)
            self.emit(f"{end_label}:")

        elif cond[0] == "==":
            if else_body:
                self.emit(f"BNEZ {t}, R0, {else_label}")
            else:
                self.emit(f"BNEZ {t}, R0, {end_label}")
            for s in body:
                self.compile_stmt(s)
            if else_body:
                self.emit(f"JAL R0, {end_label}")
                self.emit(f"{else_label}:")
                for s in else_body:
                    self.compile_stmt(s)
            self.emit(f"{end_label}:")

    def compile_while(self, stmt):
        cond = stmt[1]
        body = stmt[2]

        start = self.new_label()
        body_label = self.new_label()
        end = self.new_label()
        t = self.temp()

        self.emit(f"{start}:")
        self.eval_condition(cond, t)

        if cond[0] == "!=":
            self.emit(f"BNEZ {t}, R0, {body_label}")
            self.emit(f"JAL R0, {end}")
        elif cond[0] == "==":
            self.emit(f"BNEZ {t}, R0, {end}")

        self.emit(f"{body_label}:")
        for s in body:
            self.compile_stmt(s)
        self.emit(f"JAL R0, {start}")
        self.emit(f"{end}:")

    def eval_condition(self, cond, t):
        # put a value in t thats nonzero when condition is true
        if cond[2][0] == "num" and cond[2][1] == 0:
            # comparing to 0, just load the value
            self.compile_expr(cond[1], t)
        else:
            # XOR the two sides - result is 0 if equal, nonzero if different
            self.compile_expr(cond[1], t)
            t2 = self.temp()
            self.compile_expr(cond[2], t2)
            self.emit(f"XOR {t}, {t}, {t2}")

    def build_constant(self, dest, val):
        # load a constant bigger than 31 using ADDI + shift + ADDI
        if val <= 31:
            self.emit(f"ADDI {dest}, R0, {val}")
            return
        for shift in range(1, 16):
            upper = val >> shift
            lower = val & ((1 << shift) - 1)
            if 0 < upper <= 31 and lower <= 31:
                self.emit(f"ADDI {dest}, R0, {upper}")
                self.emit(f"SL {dest}, {dest}, 0, {shift}")
                if lower > 0:
                    self.emit(f"ADDI {dest}, {dest}, {lower}")
                return
        raise Exception(f"constant {val} too large to build")


# ---- main ----

if len(sys.argv) < 2:
    print("usage: python3 compiler.py <file.c|file.asm> [hex|bin]")
    sys.exit(0)

filename = sys.argv[1]
fmt = sys.argv[2] if len(sys.argv) > 2 else "hex"
if fmt not in ("hex", "bin"):
    print("format must be 'hex' or 'bin'")
    sys.exit(1)

with open(filename) as f:
    source = f.read()

if filename.endswith(".asm") or filename.endswith(".s"):
    code = assemble(source)
else:
    tokens = tokenize(source)
    tree = Parser(tokens).parse_program()
    asm = CodeGen().compile(tree)
    print("--- assembly ---")
    print(asm)
    print()
    code = assemble(asm)

for word in code:
    if fmt == "bin":
        print(f"{word:016b}")
    else:
        print(f"{word:04X}")