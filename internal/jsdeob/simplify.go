package jsdeob

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/token"
)

// simplify applies the small, always-safe rewrites that make obfuscator
// output readable once strings are back: folding 'ht'+'tp:' chains produced
// by splitStrings, turning obj['key'] into obj.key, and spelling out the
// !![] / ![] booleans. Each rewrite is purely syntactic and keeps semantics.
//
// It runs a single bottom-up pass; the caller loops until the source stops
// changing, which handles anything that only becomes foldable after an
// earlier replacement.
func simplify(src string) string {
	prog, err := parse(src)
	if err != nil {
		return src
	}
	var edits []edit
	walk(prog, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.IfStatement:
			// Dead code injection guards blocks with 'abc' === 'abc'.
			// Once that folds to a boolean, keep only the live branch.
			b, ok := x.Test.(*ast.BooleanLiteral)
			if !ok {
				return true
			}
			live := x.Consequent
			if !b.Value {
				live = x.Alternate
			}
			text := ";"
			if live != nil {
				text = src[idx(live.Idx0()):idx(live.Idx1())]
				if _, isBlock := live.(*ast.BlockStatement); !isBlock {
					text = "{" + text + "}"
				}
			}
			edits = append(edits, edit{idx(x.Idx0()), idx(x.Idx1()), text})
			return false
		case *ast.BinaryExpression:
			if b, ok := literalCompare(x); ok {
				edits = append(edits, edit{idx(x.Idx0()), idx(x.Idx1()), fmt.Sprint(b)})
				return false
			}
			if x.Operator != token.PLUS {
				return true
			}
			if s, ok := constString(x); ok {
				edits = append(edits, edit{idx(x.Idx0()), idx(x.Idx1()), quote(s)})
				return false
			}
		case *ast.NumberLiteral:
			// The obfuscator writes every integer in hex. Ports and sizes
			// are a lot easier to read in decimal.
			if !strings.HasPrefix(x.Literal, "0x") && !strings.HasPrefix(x.Literal, "0X") {
				return true
			}
			v, err := strconv.ParseUint(x.Literal[2:], 16, 53)
			if err != nil {
				return true
			}
			text := strconv.FormatUint(v, 10)
			if end := idx(x.Idx1()); end < len(src) && src[end] == '.' {
				text = "(" + text + ")" // 0x10.toString() is valid, 16.toString() isn't
			}
			edits = append(edits, edit{idx(x.Idx0()), idx(x.Idx1()), text})
		case *ast.UnaryExpression:
			if b, ok := arrayBool(x); ok {
				edits = append(edits, edit{idx(x.Idx0()), idx(x.Idx1()), fmt.Sprint(b)})
				return false
			}
		case *ast.BracketExpression:
			lit, ok := x.Member.(*ast.StringLiteral)
			if !ok || !identRE.MatchString(lit.Value.String()) {
				return true
			}
			// a?.['x'] must become a?.x, not a?..x
			lb := idx(x.LeftBracket)
			prefix := "."
			if before := strings.TrimRight(src[:lb], " \t\r\n"); strings.HasSuffix(before, "?.") {
				prefix = ""
			}
			edits = append(edits, edit{lb, idx(x.RightBracket) + 1, prefix + lit.Value.String()})
		}
		return true
	})
	return apply(src, edits)
}

// cleanup runs simplify and proxy inlining to a fixed point. It's what
// non-obfuscated or partially deobfuscated input gets.
func cleanup(src string, max int) string {
	for i := 0; i < max; i++ {
		next := inlineProxies(simplify(src))
		if next == src {
			break
		}
		src = next
	}
	return src
}

var identRE = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)

// constString returns the value of an expression made only of string
// literals joined with +. Number operands are refused on purpose: 'a'+1+2 and
// 1+2+'a' differ and it's not worth modelling.
func constString(e ast.Expression) (string, bool) {
	switch x := e.(type) {
	case *ast.StringLiteral:
		return x.Value.String(), true
	case *ast.TemplateLiteral:
		if x.Tag == nil && len(x.Expressions) == 0 && len(x.Elements) == 1 && x.Elements[0].Valid {
			return x.Elements[0].Parsed.String(), true
		}
	case *ast.BinaryExpression:
		if x.Operator != token.PLUS {
			return "", false
		}
		l, ok := constString(x.Left)
		if !ok {
			return "", false
		}
		r, ok := constString(x.Right)
		if !ok {
			return "", false
		}
		return l + r, true
	}
	return "", false
}

// literalCompare folds 'a' === 'b' style comparisons between two string
// literals.
func literalCompare(x *ast.BinaryExpression) (bool, bool) {
	l, ok := x.Left.(*ast.StringLiteral)
	if !ok {
		return false, false
	}
	r, ok := x.Right.(*ast.StringLiteral)
	if !ok {
		return false, false
	}
	eq := l.Value.String() == r.Value.String()
	switch x.Operator {
	case token.STRICT_EQUAL, token.EQUAL:
		return eq, true
	case token.STRICT_NOT_EQUAL, token.NOT_EQUAL:
		return !eq, true
	}
	return false, false
}

// arrayBool recognises !![] (true) and ![] (false).
func arrayBool(u *ast.UnaryExpression) (bool, bool) {
	if u.Operator != token.NOT {
		return false, false
	}
	if arr, ok := u.Operand.(*ast.ArrayLiteral); ok && len(arr.Value) == 0 {
		return false, true
	}
	inner, ok := u.Operand.(*ast.UnaryExpression)
	if !ok || inner.Operator != token.NOT {
		return false, false
	}
	if arr, ok := inner.Operand.(*ast.ArrayLiteral); ok && len(arr.Value) == 0 {
		return true, true
	}
	return false, false
}

// quote renders s as a single-quoted JS string literal that parses back to
// exactly s.
func quote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('\'')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, `\x%02x`, s[i])
			i++
			continue
		}
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			b.WriteString(`\'`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case 0x2028:
			b.WriteString(` `)
		case 0x2029:
			b.WriteString(` `)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				b.WriteRune(r)
			}
		}
		i += size
	}
	b.WriteByte('\'')
	return b.String()
}

// collectStrings returns every string literal and static template chunk in
// src, deduplicated, in order of first appearance.
func collectStrings(src string) []string {
	prog, err := parse(src)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	walk(prog, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.StringLiteral:
			add(x.Value.String())
		case *ast.TemplateElement:
			if x.Valid {
				add(x.Parsed.String())
			}
		}
		return true
	})
	return out
}
