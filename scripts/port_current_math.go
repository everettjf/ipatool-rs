// Development-only translation of pinned UnfairPlay scalar arithmetic.
// Cargo uses checked-in Rust output; no Go executable is used at runtime.
package main

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const pin = "b3a7a432da2047a0d4f1ed5a3152c538a5497183"

var selected = []string{
	"outer_table_masks.go", "outer_temporaries.go", "outer_state_transitions.go",
	"outer_complex_masks_semantic.go", "outer_optional_index_semantic.go",
	"outer_writer_seed_semantic.go", "outer_digest_counter.go",
	"outer_front_semantic.go", "outer_preround_semantic.go", "outer_hook_seeds.go",
	"outer_postround.go", "outer_table_schedule.go",
	"current_outer.go", "outer_digest_step.go",
}

var info = &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
var globals = map[string]bool{}
var mutable map[string]bool
var capital = regexp.MustCompile(`([a-z0-9])([A-Z])`)

func snake(name string) string { return strings.ToLower(capital.ReplaceAllString(name, "${1}_${2}")) }
func ident(name string) string {
	if globals[name] {
		return strings.ToUpper(snake(name))
	}
	return snake(name)
}
func rustType(t types.Type) string {
	if t == nil {
		panic("missing expression type")
	}
	if array, ok := t.Underlying().(*types.Array); ok {
		return fmt.Sprintf("[%s; %d]", rustType(array.Elem()), array.Len())
	}
	b, ok := t.Underlying().(*types.Basic)
	if !ok {
		panic(fmt.Sprintf("unsupported scalar type %s", t))
	}
	switch b.Kind() {
	case types.Uint8:
		return "u8"
	case types.Uint16:
		return "u16"
	case types.Uint32:
		return "u32"
	case types.Uint64:
		return "u64"
	case types.Int8:
		return "i8"
	case types.Int16:
		return "i16"
	case types.Int32:
		return "i32"
	case types.Int64:
		return "i64"
	case types.Int:
		return "isize"
	case types.Bool, types.UntypedBool:
		return "bool"
	case types.UntypedInt:
		return "u32"
	default:
		panic(fmt.Sprintf("unsupported basic type %s", t))
	}
}
func expr(node ast.Expr) string {
	switch n := node.(type) {
	case *ast.Ident:
		return ident(n.Name)
	case *ast.IndexExpr:
		return expr(n.X) + "[(" + expr(n.Index) + ") as usize]"
	case *ast.SelectorExpr:
		return expr(n.X) + "." + snake(n.Sel.Name)
	case *ast.BasicLit:
		if n.Kind != token.INT {
			panic("non-integer scalar literal")
		}
		return n.Value + rustType(info.TypeOf(n))
	case *ast.ParenExpr:
		return "(" + expr(n.X) + ")"
	case *ast.BinaryExpr:
		x, y := expr(n.X), expr(n.Y)
		switch n.Op {
		case token.ADD:
			return "(" + x + ").wrapping_add(" + y + ")"
		case token.SUB:
			return "(" + x + ").wrapping_sub(" + y + ")"
		case token.MUL:
			return "(" + x + ").wrapping_mul(" + y + ")"
		case token.AND_NOT:
			return "(" + x + " & !(" + y + "))"
		default:
			return "(" + x + " " + n.Op.String() + " " + y + ")"
		}
	case *ast.UnaryExpr:
		switch n.Op {
		case token.XOR, token.NOT:
			return "!(" + expr(n.X) + ")"
		case token.SUB:
			return "(" + expr(n.X) + ").wrapping_neg()"
		default:
			panic("unsupported unary operator")
		}
	case *ast.CompositeLit:
		items := make([]string, len(n.Elts))
		for i, e := range n.Elts {
			items[i] = expr(e)
		}
		if _, ok := info.TypeOf(n).Underlying().(*types.Slice); ok {
			return "&[" + strings.Join(items, ", ") + "]"
		}
		return "[" + strings.Join(items, ", ") + "]"
	case *ast.SliceExpr:
		if n.Low != nil || n.High != nil || n.Max != nil {
			panic("bounded scalar slice")
		}
		if id, ok := n.X.(*ast.Ident); ok && globals[id.Name] {
			return expr(n.X)
		}
		return "&" + expr(n.X) + "[..]"
	case *ast.CallExpr:
		args := make([]string, len(n.Args))
		for i, a := range n.Args {
			args[i] = expr(a)
		}
		if cast, ok := n.Fun.(*ast.Ident); ok {
			if obj, ok := info.Uses[cast].(*types.TypeName); ok {
				if len(args) != 1 {
					panic("invalid cast")
				}
				return "(" + args[0] + " as " + rustType(obj.Type()) + ")"
			}
		}
		if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "bits" && sel.Sel.Name == "RotateLeft32" {
				return "(" + args[0] + ").rotate_left((" + args[1] + ") as u32)"
			}
			panic("unsupported scalar selector call")
		}
		return expr(n.Fun) + "(" + strings.Join(args, ", ") + ")"
	default:
		panic(fmt.Sprintf("unsupported scalar expression %T", node))
	}
}

func stmt(node ast.Stmt) string {
	switch n := node.(type) {
	case *ast.ReturnStmt:
		out := make([]string, len(n.Results))
		for i, r := range n.Results {
			out[i] = expr(r)
		}
		if len(out) > 1 {
			return "return (" + strings.Join(out, ", ") + ");\n"
		}
		return "return " + strings.Join(out, "") + ";\n"
	case *ast.AssignStmt:
		if len(n.Lhs) > 1 && len(n.Lhs) == len(n.Rhs) && n.Tok == token.DEFINE {
			var left, right []string
			for i, l := range n.Lhs {
				name := expr(l)
				if id, ok := l.(*ast.Ident); ok && mutable[id.Name] {
					name = "mut " + name
				}
				left = append(left, name)
				right = append(right, expr(n.Rhs[i]))
			}
			return "let (" + strings.Join(left, ", ") + ") = (" + strings.Join(right, ", ") + ");\n"
		}
		if len(n.Lhs) != 1 || len(n.Rhs) != 1 {
			panic("unsupported assignment shape")
		}
		name := expr(n.Lhs[0])
		if n.Tok == token.DEFINE {
			left := n.Lhs[0].(*ast.Ident)
			prefix := "let "
			if mutable[left.Name] {
				prefix += "mut "
			}
			return prefix + name + ": " + rustType(info.TypeOf(left)) + " = " + expr(n.Rhs[0]) + ";\n"
		}
		if n.Tok == token.ASSIGN {
			return name + " = " + expr(n.Rhs[0]) + ";\n"
		}
		op := strings.TrimSuffix(n.Tok.String(), "=")
		if op == "+" || op == "-" || op == "*" {
			method := map[string]string{"+": "wrapping_add", "-": "wrapping_sub", "*": "wrapping_mul"}[op]
			return name + " = " + name + "." + method + "(" + expr(n.Rhs[0]) + ");\n"
		}
		return name + " " + n.Tok.String() + " " + expr(n.Rhs[0]) + ";\n"
	case *ast.IfStmt:
		if n.Init != nil {
			panic("unsupported scalar if initializer")
		}
		out := "if " + expr(n.Cond) + " {\n" + block(n.Body) + "}\n"
		if n.Else != nil {
			out = strings.TrimSuffix(out, "\n") + " else " + stmt(n.Else)
		}
		return out
	case *ast.BlockStmt:
		return "{\n" + block(n) + "}\n"
	default:
		panic(fmt.Sprintf("unsupported scalar statement %T", node))
	}
}

func special(fn *ast.FuncDecl) bool {
	name := fn.Name.Name
	if name != "outerFrontWords" && name != "applyOuterPreRound" && name != "deriveOuterHookSeedsWithCore" {
		return false
	}
	mutable = map[string]bool{}
	if name == "outerFrontWords" {
		fmt.Println("pub(super) fn front_words(table: &[u32;167], base:u32, digest:&super::Digest) -> ([u32;5],u32) {")
	} else if name == "applyOuterPreRound" {
		fmt.Println("pub(super) fn pre_round(table: &[u32;167], base:u32, state:&mut super::OuterState) -> bool {")
		fmt.Println("if base>=167 || state.hardware_index>=6 {return false;}")
		fmt.Println("let tap=|offset:u32|table[((base+offset)%167) as usize];")
		fmt.Println("let h=|offset:isize|u32::from(state.hardware[((state.hardware_index as isize+offset) as usize)%6]);")
		fmt.Println("let c=|offset:isize|u32::from(state.codec[offset as usize]);")
	} else {
		fmt.Println("pub(super) fn hook_seeds(table: &[u32;167], base:u32, digest:&super::Digest, word2_core:u32) -> (u32,u32,u32) {")
	}
	for _, s := range fn.Body.List[1:] {
		if a, ok := s.(*ast.AssignStmt); ok {
			if _, closure := a.Rhs[0].(*ast.FuncLit); closure {
				continue
			}
		}
		if ret, ok := s.(*ast.ReturnStmt); ok && name != "applyOuterPreRound" {
			if name == "outerFrontWords" {
				fmt.Printf("return (%s,%s);\n", expr(ret.Results[0]), expr(ret.Results[1]))
			} else {
				fmt.Println("return (even,odd,tail);")
			}
			continue
		}
		fmt.Print(stmt(s))
	}
	fmt.Println("}")
	return true
}

func digestMap(name string, literal *ast.CompositeLit) {
	fmt.Printf("pub(super) const %s: [[&[(u32,u32)];5];%d] = [\n", name, len(literal.Elts))
	fields := []string{"x27", "residual", "x4", "x10", "x28"}
	for _, item := range literal.Elts {
		mapping := map[string]*ast.CompositeLit{}
		for _, e := range item.(*ast.CompositeLit).Elts {
			kv := e.(*ast.KeyValueExpr)
			mapping[kv.Key.(*ast.Ident).Name] = kv.Value.(*ast.CompositeLit)
		}
		fmt.Print("[")
		for _, field := range fields {
			fmt.Print("&[")
			if value := mapping[field]; value != nil {
				for _, route := range value.Elts {
					pair := route.(*ast.CompositeLit).Elts
					fmt.Printf("(%s,%s),", pair[0].(*ast.BasicLit).Value, pair[1].(*ast.BasicLit).Value)
				}
			}
			fmt.Print("],")
		}
		fmt.Println("],")
	}
	fmt.Println("];")
}
func block(b *ast.BlockStmt) string {
	var out strings.Builder
	for _, s := range b.List {
		out.WriteString(stmt(s))
	}
	return out.String()
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: go run scripts/port_current_math.go /path/to/unfairplay")
	}
	root := os.Args[1]
	sha, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil || strings.TrimSpace(string(sha)) != pin {
		panic("upstream revision does not match pin")
	}
	args := []string{"-C", root, "diff", "--quiet", "HEAD", "--"}
	for _, name := range selected {
		args = append(args, "internal/recovery/"+name)
	}
	if err := exec.Command("git", args...).Run(); err != nil {
		panic("selected upstream arithmetic is modified")
	}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(filepath.Join(root, "internal/recovery"))
	if err != nil {
		panic(err)
	}
	var files []*ast.File
	byName := map[string]*ast.File{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(root, "internal/recovery", name), nil, 0)
		if err != nil {
			panic(err)
		}
		files = append(files, f)
		byName[name] = f
		for _, decl := range f.Decls {
			if gen, ok := decl.(*ast.GenDecl); ok && (gen.Tok == token.CONST || gen.Tok == token.VAR) {
				for _, spec := range gen.Specs {
					for _, n := range spec.(*ast.ValueSpec).Names {
						globals[n.Name] = true
					}
				}
			}
		}
	}
	// Type errors from the sibling internal package import are immaterial here;
	// every selected expression must still have a resolved supported scalar type.
	config := types.Config{Importer: importer.Default(), Error: func(error) {}}
	_, _ = config.Check("github.com/DrWhax/unfairplay/internal/recovery", fset, files, info)
	fmt.Println("// Generated from UnfairPlay " + pin + " (MIT).")
	fmt.Println("// Development generator: scripts/port_current_math.go. Rust runtime only.")
	fmt.Println("#![allow(unused_parens, clippy::unnecessary_cast, clippy::double_parens, clippy::needless_return, clippy::too_many_arguments, clippy::manual_range_contains)]")
	fmt.Println("use super::polynomial as outer_boolean_mask;\nuse super::polynomial as outer_front_polynomial;\nuse super::polynomial as outer_hook_polynomial;")
	for _, file := range selected {
		for _, decl := range byName[file].Decls {
			if gen, ok := decl.(*ast.GenDecl); ok {
				for _, spec := range gen.Specs {
					v, ok := spec.(*ast.ValueSpec)
					if !ok || len(v.Names) != 1 || len(v.Values) != 1 {
						continue
					}
					name := strings.ToUpper(snake(v.Names[0].Name))
					// The folded decoder no longer reads this historical phase marker.
					if name == "OUTER_OPTIONAL_PHASE_OFFSET" {
						continue
					}
					if gen.Tok == token.CONST {
						fmt.Printf("pub(super) const %s: %s = %s;\n", name, rustType(info.TypeOf(v.Names[0])), expr(v.Values[0]))
						continue
					}
					literal, ok := v.Values[0].(*ast.CompositeLit)
					if !ok {
						continue
					}
					array, ok := literal.Type.(*ast.ArrayType)
					if !ok {
						continue
					}
					element, ok := array.Elt.(*ast.Ident)
					if ok && element.Name == "outerDigestByteMap" {
						digestMap(name, literal)
						continue
					}
					if !ok || !strings.HasSuffix(element.Name, "Term") {
						fmt.Printf("pub(super) const %s: %s = %s;\n", name, rustType(info.TypeOf(literal)), expr(literal))
						continue
					}
					fmt.Printf("pub(super) const %s: &[(u32,u64)] = &[\n", name)
					for _, term := range literal.Elts {
						values := term.(*ast.CompositeLit).Elts
						fmt.Printf("(%su32,%su64),\n", values[0].(*ast.BasicLit).Value, values[1].(*ast.BasicLit).Value)
					}
					fmt.Println("];")
				}
				continue
			}
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			// This write is overwritten before any observable read in the
			// current semantic iteration; keep the unused helper out of Rust.
			if fn.Name.Name == "outerTableLane19NextS0" {
				continue
			}
			if special(fn) {
				continue
			}
			scalar := true
			for _, field := range fn.Type.Params.List {
				_, basic := info.TypeOf(field.Type).Underlying().(*types.Basic)
				scalar = scalar && basic
			}
			for _, field := range fn.Type.Results.List {
				_, basic := info.TypeOf(field.Type).Underlying().(*types.Basic)
				scalar = scalar && basic
			}
			if !scalar {
				continue
			}
			mutable = map[string]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if a, ok := n.(*ast.AssignStmt); ok && a.Tok != token.DEFINE {
					for _, l := range a.Lhs {
						if id, ok := l.(*ast.Ident); ok {
							mutable[id.Name] = true
						}
					}
				}
				return true
			})
			var params, results []string
			for _, field := range fn.Type.Params.List {
				for _, n := range field.Names {
					name := ident(n.Name)
					if mutable[n.Name] {
						name = "mut " + name
					}
					params = append(params, name+": "+rustType(info.TypeOf(field.Type)))
				}
			}
			for _, field := range fn.Type.Results.List {
				results = append(results, rustType(info.TypeOf(field.Type)))
			}
			ret := strings.Join(results, ", ")
			if len(results) > 1 {
				ret = "(" + ret + ")"
			}
			fmt.Printf("\n// %s:%s\npub(super) fn %s(%s) -> %s {\n%s}\n", file, fn.Name.Name, snake(fn.Name.Name), strings.Join(params, ", "), ret, block(fn.Body))
		}
	}
}
