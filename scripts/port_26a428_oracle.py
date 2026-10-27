#!/usr/bin/env python3
"""Translate checked straight-line FairPlay Go evaluators into Rust.

This is a source-generation tool, not a runtime dependency. Pass the original
generated_26a428.go and the Rust output path. Unsupported syntax fails closed.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path


TOKEN = re.compile(r'\s*(0x[0-9a-fA-F]+|[0-9]+|"[^"]*"|[A-Za-z_][A-Za-z_0-9.]*|<<|>>|[+*^&|(),\[\]-])')
PRECEDENCE = {"|": 1, "^": 1, "+": 1, "-": 1, "*": 2, "<<": 2, ">>": 2, "&": 2}


class Expression:
    def __init__(self, source: str):
        self.source = source
        self.tokens: list[str] = []
        offset = 0
        while offset < len(source):
            match = TOKEN.match(source, offset)
            if match is None:
                raise ValueError(f"unrecognized expression syntax: {source[offset:]!r}")
            self.tokens.append(match.group(1))
            offset = match.end()
        self.index = 0

    def take(self) -> str:
        if self.index >= len(self.tokens):
            raise ValueError(f"truncated expression: {self.source}")
        token = self.tokens[self.index]
        self.index += 1
        return token

    def peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def expect(self, token: str) -> None:
        actual = self.take()
        if actual != token:
            raise ValueError(f"expected {token!r}, got {actual!r}: {self.source}")

    def parse(self, precedence: int = 0) -> str:
        token = self.take()
        if token == "(":
            left = self.parse()
            self.expect(")")
        elif token == "-":
            left = f"(0u64).wrapping_sub({self.parse(3)})"
        elif token == "^":
            left = f"(!{self.parse(3)})"
        elif token == "s.x":
            self.expect("[")
            register = self.take()
            self.expect("]")
            if not register.isdecimal():
                raise ValueError("dynamic oracle register index")
            left = f"s.registers[{register}]"
        elif token == "s.sp":
            left = "s.sp"
        elif token in ("s.n", "s.z", "s.c", "s.v"):
            left = f"s.flags[{dict(n=0, z=1, c=2, v=3)[token[2:]]}]"
        elif token.startswith('"'):
            left = token
        elif token in ("true", "false"):
            left = token
        elif token.startswith("0x") or token.isdecimal():
            left = f"{token}u64"
        elif self.peek() == "(":
            self.take()
            args = []
            if self.peek() != ")":
                while True:
                    args.append(self.parse())
                    if self.peek() != ",":
                        break
                    self.take()
            self.expect(")")
            left = self.call(token, args)
        elif re.fullmatch(r"(?:value|old|restore)\d+[a-z]?|selected", token):
            left = token
        else:
            raise ValueError(f"unsupported expression token {token!r}: {self.source}")
        while (operator := self.peek()) in PRECEDENCE and PRECEDENCE[operator] > precedence:
            self.take()
            right = self.parse(PRECEDENCE[operator])
            if operator == "+":
                left = f"({left}).wrapping_add({right})"
            elif operator == "-":
                left = f"({left}).wrapping_sub({right})"
            elif operator == "*":
                left = f"({left}).wrapping_mul({right})"
            elif operator == "<<":
                left = f"({left}).wrapping_shl({right} as u32)"
            elif operator == ">>":
                left = f"({left}).wrapping_shr({right} as u32)"
            else:
                left = f"({left} {operator} {right})"
        return left

    @staticmethod
    def call(name: str, args: list[str]) -> str:
        def arity(count: int) -> None:
            if len(args) != count:
                raise ValueError(f"{name} expected {count} arguments")

        if name in ("uint64", "uint", "int"):
            arity(1)
            return f"({args[0]} as u64)"
        if name == "uint32":
            arity(1)
            return f"({args[0]} as u32 as u64)"
        if name == "uint8":
            arity(1)
            return f"({args[0]} as u8 as u64)"
        if name == "signExtend32":
            arity(1)
            return f"sign_extend32({args[0]} as u32)"
        if name == "multiplyHigh64":
            arity(2)
            return f"((({args[0]} as u128).wrapping_mul({args[1]} as u128) >> 64) as u64)"
        if name == "unsignedDivide":
            arity(3)
            return f"unsigned_divide({args[0]}, {args[1]}, {args[2]} as u32)"
        if name == "addOffset":
            arity(2)
            return f"add_offset({args[0]}, {args[1]} as i64)"
        if name in ("shiftLeft", "shiftRight", "shiftRightArithmetic", "rotateRight"):
            arity(3)
            rust = {"shiftLeft": "shift_left", "shiftRight": "shift_right", "shiftRightArithmetic": "shift_right_arithmetic", "rotateRight": "rotate_right"}[name]
            return f"{rust}({args[0]}, {args[1]}, {args[2]} as u32)"
        if name == "bitMask":
            arity(2)
            return f"bit_mask({args[0]} as u32, {args[1]} as u32)"
        if name == "insertBits":
            arity(5)
            return f"insert_bits({args[0]}, {args[1]}, {args[2]} as u32, {args[3]} as u32, {args[4]} as u32)"
        if name == "extractPair":
            arity(4)
            return f"extract_pair({args[0]}, {args[1]}, {args[2]}, {args[3]} as u32)"
        if name == "boolValue":
            arity(1)
            return f"bool_value({args[0]})"
        if name == "selectValue":
            arity(3)
            return f"select_value({', '.join(args)})"
        if name == "s.condition":
            arity(1)
            return f"s.condition({args[0]})"
        if name == "s.load":
            arity(2)
            return f"s.load({args[0]}, {args[1]} as usize)?"
        if name == "s.storeValue":
            arity(3)
            return f"s.store_value({args[0]}, {args[1]}, {args[2]} as usize)?"
        if name == "s.beforeFault":
            arity(2)
            return f"s.before_fault({', '.join(args)})?"
        if name == "s.afterFault":
            arity(4)
            return f"s.after_fault({', '.join(args)})"
        if name == "s.compare32":
            arity(2)
            return f"s.compare32({args[0]} as u32, {args[1]} as u32)"
        if name == "s.compare64":
            arity(2)
            return f"s.compare64({args[0]}, {args[1]})"
        if name == "s.addWithCarry":
            arity(4)
            return f"s.add_with_carry({args[0]}, {args[1]}, {args[2]}, {args[3]} as u32)"
        raise ValueError(f"unsupported generated call {name}")


def expression(source: str) -> str:
    parser = Expression(source)
    result = parser.parse()
    if parser.peek() is not None:
        raise ValueError(f"trailing expression syntax: {source}")
    return result


def translate(
    source: str,
    go_function: str = "runGenerated",
    rust_function: str = "run_generated",
    generator_name: str = "scripts/port_26a428_oracle.py",
) -> str:
    marker = f"func {go_function}(s *state, selected fault) error {{"
    if source.count(marker) != 1:
        raise ValueError("expected one checked generated function")
    body = source.split(marker, 1)[1].splitlines()
    rendered = []
    index = 0
    while index < len(body):
        line = body[index].strip()
        index += 1
        if not line or line.startswith("//"):
            continue
        if line == "return nil":
            rendered.append("    Ok(())")
            continue
        if line == "}":
            if any(value.strip() for value in body[index:]):
                raise ValueError("unexpected generated block close")
            break
        if line.startswith("if err != nil {"):
            if [value.strip() for value in body[index:index+2]] != ["return err", "}"]:
                raise ValueError("unsupported generated error branch")
            index += 2
            continue
        match = re.fullmatch(r'if _, err := runRawSourceKernelLoop\(s, "([a-z-]+)"\); err != nil \{', line)
        if match:
            if [value.strip() for value in body[index:index+2]] != ["return err", "}"]:
                raise ValueError("unsupported raw source kernel loop branch")
            index += 2
            rendered.append(f'    run_raw_source_kernel_loop(s, "{match.group(1)}")?;')
            continue
        if line == "if s.x[9] == 0x1005BA520 {":
            if [value.strip() for value in body[index:index+4]] != [
                "if err := runRawSourceOptionalKernel(s, fault{}); err != nil {",
                "return err", "}", "}",
            ]:
                raise ValueError("unsupported raw source optional branch")
            index += 4
            rendered.append("    if s.registers[9] == 0x1005ba520 { run_raw_source_optional_kernel(s, OracleFault::NONE)?; }")
            continue
        match = re.fullmatch(r"if err := (s\.storeValue\(.*\)); err != nil \{", line)
        if match:
            if [value.strip() for value in body[index:index+2]] != ["return err", "}"]:
                raise ValueError("unsupported generated store error branch")
            index += 2
            rendered.append(f"    {expression(match.group(1))};")
            continue
        match = re.fullmatch(r"(value\d+[a-z]?), err := (s\.load\(.*\))", line)
        if match:
            rendered.append(f"    let {match.group(1)} = {expression(match.group(2))};")
            continue
        match = re.fullmatch(r"(old\d+), (restore\d+), err := (s\.beforeFault\(.*\))", line)
        if match:
            rendered.append(f"    let ({match.group(1)}, {match.group(2)}) = {expression(match.group(3))};")
            continue
        match = re.fullmatch(r"s\.x\[(\d+)\] = (.*)", line)
        if match:
            rendered.append(f"    s.registers[{match.group(1)}] = {expression(match.group(2))};")
            continue
        if line.startswith("s.afterFault(") or line.startswith("s.compare32(") or line.startswith("s.compare64("):
            rendered.append(f"    {expression(line)};")
            continue
        if line.startswith("_ = s.addWithCarry("):
            rendered.append(f"    let _ = {expression(line[4:])};")
            continue
        raise ValueError(f"unsupported generated statement: {line}")
    digest = hashlib.sha256(source.encode()).hexdigest()
    if go_function == "runGenerated":
        origin = "generated_26a428.go"
        allow = "clippy::all, unused_parens"
    else:
        origin = f"{go_function} Go source"
        allow = "clippy::all, unused_parens, unused_variables, dead_code"
    header = (f"// Generated from checked {origin}, SHA-256 {digest}.\n"
              f"// Regenerate with {generator_name}; Rust runtime has no Go dependency.\n"
              f"#[rustfmt::skip]\n#[allow({allow})]\n"
              f"fn {rust_function}(s: &mut OracleState<'_>, selected: OracleFault) -> Result<()> {{\n")
    return header + "\n".join(rendered) + "\n}\n"


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: port_26a428_oracle.py generated_26a428.go fairplay_26a428_generated.rs")
    Path(sys.argv[2]).write_text(translate(Path(sys.argv[1]).read_text()))
