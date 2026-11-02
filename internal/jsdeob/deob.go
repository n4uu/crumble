// Package jsdeob undoes the string array transform of javascript-obfuscator,
// which is what every OtterCookie and BeaverTail build seen so far has been
// run through.
//
// The obfuscator moves every string literal into one array, rotates that
// array by a seed-dependent amount at startup, and replaces each literal with
// a call like a0_0x1481(0x1e5, 'Jsi4') that indexes into it (optionally
// base64- or RC4-decoding the entry on the way out). Call sites rarely hit
// the decoder directly: they go through local aliases and "wrapper" functions
// that shift the index by a constant, sometimes chained several deep.
//
// Rather than reimplementing the rotation and both decoders (which change
// between obfuscator releases), this package finds the bootstrap code in the
// AST, runs exactly that code in an isolated goja VM, defines every alias and
// wrapper it can prove is a pure pass-through, and then evaluates each call
// site whose arguments are all constants. The rest of the sample is never
// executed here; see package sandbox for that.
package jsdeob

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dop251/goja"
	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	"github.com/dop251/goja/token"
)

// Result describes what was recovered from one script.
type Result struct {
	Source string // the script with decoder calls replaced by literals

	ArrayName string   // the string array holder (function or variable)
	ArraySize int      // number of entries in the array literal
	Decoders  []string // decoder functions that index into the array
	Rotated   bool     // a rotation IIFE was found and run
	Encoding  string   // "none", "base64", "rc4" or "unknown"

	Aliases  int // variable aliases of a decoder that were resolved
	Wrappers int // wrapper functions that were resolved
	Replaced int // call sites replaced with a literal
	Failed   int // call sites that looked constant but failed to evaluate
	Passes   int

	// Strings holds every string literal in the final source, deduplicated
	// in order of first appearance. This is what IOC extraction runs over.
	Strings []string
}

// ErrNoStringArray is returned when the script doesn't contain a string array
// bootstrap. Plain (or differently obfuscated) scripts still get a Result
// with Strings filled in, so callers can treat this as informational.
var ErrNoStringArray = errors.New("no javascript-obfuscator string array found")

// Options tunes the deobfuscator. The zero value is usable.
type Options struct {
	// Timeout bounds every evaluation in the VM. The bootstrap is supposed
	// to be a few hundred operations; a sample that turns it into an
	// infinite loop gets interrupted instead of hanging the caller.
	Timeout time.Duration
	// KeepBootstrap leaves the string array, decoder and rotation code in
	// the output instead of removing them.
	KeepBootstrap bool
	// MaxPasses bounds the replace/fold loop. Chained wrappers need one
	// pass per link in the worst case.
	MaxPasses int
}

func (o *Options) defaults() {
	if o.Timeout == 0 {
		o.Timeout = 10 * time.Second
	}
	if o.MaxPasses == 0 {
		o.MaxPasses = 8
	}
}

// Deobfuscate recovers the strings of a javascript-obfuscator protected
// script. The returned Result is non-nil whenever the script parses, even if
// err is ErrNoStringArray.
func Deobfuscate(src string, opts Options) (*Result, error) {
	opts.defaults()

	prog, err := parse(src)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	res := &Result{Source: src, Encoding: "unknown"}

	boot := findBootstrap(prog, src)
	if boot == nil {
		res.Source = cleanup(src, opts.MaxPasses)
		res.Strings = collectStrings(res.Source)
		return res, ErrNoStringArray
	}
	res.ArrayName = boot.holder
	res.ArraySize = boot.size
	res.Decoders = boot.decoders
	res.Rotated = boot.rotation != ""
	res.Encoding = boot.encoding

	vm := goja.New()
	if err := runBounded(vm, boot.code(), opts.Timeout); err != nil {
		return res, fmt.Errorf("bootstrap: %w", err)
	}

	known := map[string]bool{}
	for _, d := range boot.decoders {
		known[d] = true
	}

	cur := src
	for pass := 0; pass < opts.MaxPasses; pass++ {
		res.Passes++
		prog, err := parse(cur)
		if err != nil {
			// A replacement produced something unparsable. That's a bug
			// here, not in the sample: stop and keep the last good text.
			res.Failed++
			break
		}

		na, nw := defineAliases(vm, prog, cur, known, opts.Timeout)
		res.Aliases += na
		res.Wrappers += nw

		edits, failed := decoderCalls(vm, prog, cur, known, boot.spans(prog, cur), opts.Timeout)
		res.Failed += failed
		res.Replaced += len(edits)

		next := inlineProxies(simplify(apply(cur, edits)))
		if next == cur {
			break
		}
		cur = next
	}

	if !opts.KeepBootstrap {
		cur = removeDead(cur, boot, known)
	}

	res.Source = cur
	res.Strings = collectStrings(cur)
	return res, nil
}

func parse(src string) (*ast.Program, error) {
	return parser.ParseFile(nil, "", src, 0, parser.WithDisableSourceMaps)
}

// runBounded evaluates code with a wall-clock limit.
func runBounded(vm *goja.Runtime, code string, limit time.Duration) error {
	timer := time.AfterFunc(limit, func() { vm.Interrupt("crumble: evaluation timed out") })
	defer timer.Stop()
	defer vm.ClearInterrupt()
	_, err := vm.RunString(code)
	return err
}

func evalString(vm *goja.Runtime, code string, limit time.Duration) (string, bool) {
	timer := time.AfterFunc(limit, func() { vm.Interrupt("crumble: evaluation timed out") })
	defer timer.Stop()
	defer vm.ClearInterrupt()
	v, err := vm.RunString(code)
	if err != nil || v == nil {
		return "", false
	}
	if _, ok := v.Export().(string); !ok {
		return "", false
	}
	return v.String(), true
}

// ---------------------------------------------------------------------------
// bootstrap discovery

type bootstrap struct {
	holder   string   // name of the array function / variable
	size     int      // entries in the array literal
	decoders []string // functions that read from the holder
	rotation string   // source of the rotation IIFE, if any
	encoding string

	pieces []string // source of holder + decoders + rotation, in order
}

func (b *bootstrap) code() string { return strings.Join(b.pieces, ";\n") }

// spans returns the byte ranges of the bootstrap statements in the current
// source. Decoder calls inside them (the rotation IIFE is full of them) must
// not be rewritten, or the bootstrap stops being runnable.
func (b *bootstrap) spans(prog *ast.Program, src string) [][2]int {
	var out [][2]int
	for _, list := range statementLists(prog) {
		for _, st := range list {
			if b.owns(st) {
				s, e := span(src, st)
				out = append(out, [2]int{s, e})
			}
		}
	}
	return out
}

func (b *bootstrap) owns(st ast.Statement) bool {
	if name, _, ok := declaredFunc(st); ok {
		if name == b.holder {
			return true
		}
		for _, d := range b.decoders {
			if name == d {
				return true
			}
		}
	}
	if name, ok := arrayVar(st); ok && name == b.holder {
		return true
	}
	return b.rotation != "" && isRotation(st, b.holder)
}

func findBootstrap(prog *ast.Program, src string) *bootstrap {
	for _, list := range statementLists(prog) {
		if b := bootstrapIn(list, src); b != nil {
			return b
		}
	}
	return nil
}

func bootstrapIn(list []ast.Statement, src string) *bootstrap {
	var b *bootstrap
	var holderStmt ast.Statement

	// The holder: either `function X(){ var a = ['..', ...]; X = function(){return a}; return X(); }`
	// (obfuscator 2.x and later) or a plain `var X = ['..', ...]` (1.x).
	for _, st := range list {
		if name, fn, ok := declaredFunc(st); ok && fn.ParameterList != nil && len(fn.ParameterList.List) == 0 {
			if n := largestStringArray(fn.Body); n >= 3 && references(fn.Body, name) {
				b = &bootstrap{holder: name, size: n}
				holderStmt = st
				break
			}
		}
		if name, ok := arrayVar(st); ok {
			b = &bootstrap{holder: name, size: largestStringArray(st)}
			holderStmt = st
			break
		}
	}
	if b == nil {
		return nil
	}

	b.pieces = append(b.pieces, stmtText(src, holderStmt))

	for _, st := range list {
		if st == holderStmt {
			continue
		}
		name, fn, ok := declaredFunc(st)
		if !ok || name == b.holder || !references(fn.Body, b.holder) {
			continue
		}
		b.decoders = append(b.decoders, name)
		text := stmtText(src, st)
		b.pieces = append(b.pieces, text)
		b.encoding = mergeEncoding(b.encoding, guessEncoding(text))
	}
	if len(b.decoders) == 0 {
		return nil
	}

	for _, st := range list {
		if isRotation(st, b.holder) {
			b.rotation = stmtText(src, st)
			b.pieces = append(b.pieces, b.rotation)
			break
		}
	}
	if b.encoding == "" {
		b.encoding = "none"
	}
	return b
}

// declaredFunc matches `function X(...) {...}` and `var/let/const X = function(...) {...}`.
func declaredFunc(st ast.Statement) (string, *ast.FunctionLiteral, bool) {
	switch s := st.(type) {
	case *ast.FunctionDeclaration:
		if s.Function != nil && s.Function.Name != nil {
			return s.Function.Name.Name.String(), s.Function, true
		}
	case *ast.VariableStatement:
		if len(s.List) == 1 {
			return bindingFunc(s.List[0])
		}
	case *ast.LexicalDeclaration:
		if len(s.List) == 1 {
			return bindingFunc(s.List[0])
		}
	}
	return "", nil, false
}

func bindingFunc(b *ast.Binding) (string, *ast.FunctionLiteral, bool) {
	id, ok := b.Target.(*ast.Identifier)
	if !ok {
		return "", nil, false
	}
	fn, ok := b.Initializer.(*ast.FunctionLiteral)
	if !ok {
		return "", nil, false
	}
	return id.Name.String(), fn, true
}

func arrayVar(st ast.Statement) (string, bool) {
	var list []*ast.Binding
	switch s := st.(type) {
	case *ast.VariableStatement:
		list = s.List
	case *ast.LexicalDeclaration:
		list = s.List
	default:
		return "", false
	}
	if len(list) != 1 {
		return "", false
	}
	id, ok := list[0].Target.(*ast.Identifier)
	if !ok {
		return "", false
	}
	arr, ok := list[0].Initializer.(*ast.ArrayLiteral)
	if !ok || len(arr.Value) < 3 {
		return "", false
	}
	for _, v := range arr.Value {
		if _, ok := v.(*ast.StringLiteral); !ok {
			return "", false
		}
	}
	return id.Name.String(), true
}

// largestStringArray returns the length of the biggest array literal under n
// whose elements are all string literals.
func largestStringArray(n any) int {
	best := 0
	walk(n, func(node ast.Node) bool {
		arr, ok := node.(*ast.ArrayLiteral)
		if !ok || len(arr.Value) <= best {
			return true
		}
		for _, v := range arr.Value {
			if _, ok := v.(*ast.StringLiteral); !ok {
				return true
			}
		}
		best = len(arr.Value)
		return true
	})
	return best
}

func references(n any, name string) bool {
	found := false
	walk(n, func(node ast.Node) bool {
		if found {
			return false
		}
		if id, ok := node.(*ast.Identifier); ok && id.Name.String() == name {
			found = true
		}
		return !found
	})
	return found
}

// isRotation matches the self-invoking function the obfuscator emits to
// rotate the array: (function(arr, target){ ... push(shift()) ... }(X, 0x8f2a1)).
func isRotation(st ast.Statement, holder string) bool {
	es, ok := st.(*ast.ExpressionStatement)
	if !ok {
		return false
	}
	expr := es.Expression
	for {
		u, ok := expr.(*ast.UnaryExpression)
		if !ok {
			break
		}
		expr = u.Operand
	}
	call, ok := expr.(*ast.CallExpression)
	if !ok {
		return false
	}
	if _, ok := call.Callee.(*ast.FunctionLiteral); !ok {
		return false
	}
	for _, a := range call.ArgumentList {
		if id, ok := a.(*ast.Identifier); ok && id.Name.String() == holder {
			return true
		}
	}
	return false
}

// guessEncoding labels a decoder by the constants it can't avoid: RC4 needs
// a 256-entry state table, base64 ships its alphabet. The obfuscator's
// alphabet starts lowercase, which is a decent tell on its own.
func guessEncoding(decoder string) string {
	hasAlphabet := strings.Contains(decoder, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=")
	hasRC4 := strings.Contains(decoder, "0x100") || strings.Contains(decoder, "256")
	switch {
	case hasAlphabet && hasRC4:
		return "rc4"
	case hasAlphabet:
		return "base64"
	}
	return ""
}

func mergeEncoding(a, b string) string {
	switch {
	case a == "" || a == b:
		return b
	case b == "":
		return a
	}
	return "mixed"
}

// ---------------------------------------------------------------------------
// aliases and wrappers

// defineAliases finds every `var X = <known>` and every function that does
// nothing but forward to a known decoder with constant-adjusted arguments,
// defines them in the VM under the same name, and adds them to known.
// Obfuscator identifiers are unique across the file, which is what makes
// hoisting nested wrappers to the VM's global scope safe.
func defineAliases(vm *goja.Runtime, prog *ast.Program, src string, known map[string]bool, limit time.Duration) (aliases, wrappers int) {
	for {
		added := false
		walk(prog, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.Binding:
				id, ok := s.Target.(*ast.Identifier)
				if !ok || known[id.Name.String()] {
					return true
				}
				name := id.Name.String()
				switch init := s.Initializer.(type) {
				case *ast.Identifier:
					if known[init.Name.String()] {
						if runBounded(vm, fmt.Sprintf("var %s = %s;", name, init.Name), limit) == nil {
							known[name] = true
							aliases++
							added = true
						}
					}
				case *ast.FunctionLiteral:
					if isWrapper(init, known) {
						code := fmt.Sprintf("var %s = %s;", name, src[idx(init.Idx0()):idx(init.Idx1())])
						if runBounded(vm, code, limit) == nil {
							known[name] = true
							wrappers++
							added = true
						}
					}
				case *ast.ArrowFunctionLiteral:
					if isArrowWrapper(init, known) {
						code := fmt.Sprintf("var %s = %s;", name, src[idx(init.Idx0()):idx(init.Idx1())])
						if runBounded(vm, code, limit) == nil {
							known[name] = true
							wrappers++
							added = true
						}
					}
				}
			case *ast.FunctionDeclaration:
				fn := s.Function
				if fn == nil || fn.Name == nil || known[fn.Name.Name.String()] {
					return true
				}
				if isWrapper(fn, known) {
					if runBounded(vm, src[idx(fn.Idx0()):idx(fn.Idx1())], limit) == nil {
						known[fn.Name.Name.String()] = true
						wrappers++
						added = true
					}
				}
			}
			return true
		})
		if !added {
			return
		}
	}
}

// isWrapper: the body is exactly `return K(args...)` where K is known and
// every argument is built only from the function's own parameters and
// literals. Anything else (closures over outer state, side effects) is left
// alone, because we can't run it faithfully out of context.
func isWrapper(fn *ast.FunctionLiteral, known map[string]bool) bool {
	if fn.Body == nil || len(fn.Body.List) != 1 {
		return false
	}
	ret, ok := fn.Body.List[0].(*ast.ReturnStatement)
	if !ok || ret.Argument == nil {
		return false
	}
	return forwards(ret.Argument, params(fn.ParameterList), known)
}

func isArrowWrapper(fn *ast.ArrowFunctionLiteral, known map[string]bool) bool {
	ps := params(fn.ParameterList)
	switch body := fn.Body.(type) {
	case *ast.ExpressionBody:
		return forwards(body.Expression, ps, known)
	case *ast.BlockStatement:
		if len(body.List) != 1 {
			return false
		}
		ret, ok := body.List[0].(*ast.ReturnStatement)
		return ok && ret.Argument != nil && forwards(ret.Argument, ps, known)
	}
	return false
}

func params(pl *ast.ParameterList) map[string]bool {
	out := map[string]bool{}
	if pl == nil {
		return out
	}
	for _, b := range pl.List {
		if id, ok := b.Target.(*ast.Identifier); ok {
			out[id.Name.String()] = true
		}
	}
	return out
}

func forwards(e ast.Expression, ps map[string]bool, known map[string]bool) bool {
	call, ok := e.(*ast.CallExpression)
	if !ok {
		return false
	}
	callee, ok := call.Callee.(*ast.Identifier)
	if !ok || !known[callee.Name.String()] {
		return false
	}
	for _, a := range call.ArgumentList {
		if !pure(a, ps) {
			return false
		}
	}
	return true
}

func pure(e ast.Expression, ps map[string]bool) bool {
	switch x := e.(type) {
	case *ast.Identifier:
		return ps[x.Name.String()]
	case *ast.NumberLiteral, *ast.StringLiteral, *ast.BooleanLiteral, *ast.NullLiteral:
		return true
	case *ast.UnaryExpression:
		return !x.Postfix && pure(x.Operand, ps)
	case *ast.BinaryExpression:
		return pure(x.Left, ps) && pure(x.Right, ps)
	}
	return false
}

// ---------------------------------------------------------------------------
// call site replacement

type edit struct {
	start, end int
	text       string
}

func decoderCalls(vm *goja.Runtime, prog *ast.Program, src string, known map[string]bool, skip [][2]int, limit time.Duration) (edits []edit, failed int) {
	walk(prog, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpression)
		if !ok {
			return true
		}
		start, end := idx(call.Idx0()), idx(call.Idx1())
		if inside(start, end, skip) {
			return false
		}
		callee, ok := call.Callee.(*ast.Identifier)
		if !ok || !known[callee.Name.String()] {
			return true
		}
		for _, a := range call.ArgumentList {
			if !constant(a) {
				return true
			}
		}
		val, ok := evalString(vm, src[start:end], limit)
		if !ok {
			failed++
			return true
		}
		edits = append(edits, edit{start, end, quote(val)})
		return false
	})
	return edits, failed
}

func constant(e ast.Expression) bool {
	switch x := e.(type) {
	case *ast.NumberLiteral, *ast.StringLiteral, *ast.BooleanLiteral, *ast.NullLiteral:
		return true
	case *ast.UnaryExpression:
		return !x.Postfix && x.Operator != token.INCREMENT && x.Operator != token.DECREMENT && constant(x.Operand)
	case *ast.BinaryExpression:
		return constant(x.Left) && constant(x.Right)
	case *ast.TemplateLiteral:
		return x.Tag == nil && len(x.Expressions) == 0
	}
	return false
}

func inside(start, end int, spans [][2]int) bool {
	for _, s := range spans {
		if start >= s[0] && end <= s[1] {
			return true
		}
	}
	return false
}

// apply splices non-overlapping edits into src. Edits nested inside an
// earlier (outer) edit are dropped.
func apply(src string, edits []edit) string {
	if len(edits) == 0 {
		return src
	}
	sort.Slice(edits, func(i, j int) bool {
		if edits[i].start != edits[j].start {
			return edits[i].start < edits[j].start
		}
		return edits[i].end > edits[j].end
	})
	var b strings.Builder
	last := 0
	for _, e := range edits {
		if e.start < last {
			continue
		}
		b.WriteString(src[last:e.start])
		b.WriteString(e.text)
		last = e.end
	}
	b.WriteString(src[last:])
	return b.String()
}

// ---------------------------------------------------------------------------
// cleanup

// removeDead drops the bootstrap and any alias or wrapper that nothing calls
// anymore. A declaration is only removed once its name has no remaining
// references, so a call site we failed to resolve keeps everything it needs.
// Wrappers that forward to other wrappers come off one layer per round.
func removeDead(src string, boot *bootstrap, known map[string]bool) string {
	names := append([]string{boot.holder}, boot.decoders...)
	for round := 0; round < 12; round++ {
		prog, err := parse(src)
		if err != nil {
			return src
		}
		uses := identifierUses(prog)

		var edits []edit
		var bootStmts []ast.Statement
		for _, list := range statementLists(prog) {
			for _, st := range list {
				if boot.owns(st) {
					bootStmts = append(bootStmts, st)
					continue
				}
				if deadForwarder(st, known, uses) {
					s, e := span(src, st)
					edits = append(edits, edit{s, eatSemicolon(src, e), ""})
					continue
				}
				edits = append(edits, deadBindingEdits(src, st, known, uses)...)
			}
		}

		// The holder, decoders and rotation reference each other, so they
		// go together, and only once nothing outside them uses any of them.
		if len(edits) == 0 && len(bootStmts) > 0 {
			inBoot := map[string]int{}
			for _, st := range bootStmts {
				walk(st, func(n ast.Node) bool {
					if id, ok := n.(*ast.Identifier); ok {
						inBoot[id.Name.String()]++
					}
					return true
				})
			}
			external := false
			for _, n := range names {
				if uses[n] > inBoot[n] {
					external = true
				}
			}
			if !external {
				for _, st := range bootStmts {
					s, e := span(src, st)
					edits = append(edits, edit{s, eatSemicolon(src, e), ""})
				}
			}
		}

		next := apply(src, edits)
		if next == src {
			break
		}
		src = next
	}
	return src
}

// deadBindingEdits handles `const a = alias, b = new Thing()`: the alias
// binding goes, its neighbour stays.
func deadBindingEdits(src string, st ast.Statement, known map[string]bool, uses map[string]int) []edit {
	return removeBindings(src, st, func(name string) bool {
		return known[name] && uses[name] == 1
	})
}

// removeBindings returns the edits that delete every binding of a var/let/
// const statement whose name satisfies dead: the whole statement if all of
// them are, otherwise each binding along with its separating comma.
func removeBindings(src string, st ast.Statement, dead func(string) bool) []edit {
	var list []*ast.Binding
	switch s := st.(type) {
	case *ast.VariableStatement:
		list = s.List
	case *ast.LexicalDeclaration:
		list = s.List
	default:
		return nil
	}
	if len(list) == 0 {
		return nil
	}
	isDead := make([]bool, len(list))
	live := 0
	for i, b := range list {
		id, ok := b.Target.(*ast.Identifier)
		isDead[i] = ok && dead(id.Name.String())
		if !isDead[i] {
			live++
		}
	}
	if live == len(list) {
		return nil
	}
	if live == 0 {
		s, e := span(src, st)
		return []edit{{s, eatSemicolon(src, e), ""}}
	}
	var edits []edit
	for i, b := range list {
		if !isDead[i] {
			continue
		}
		if i+1 < len(list) {
			edits = append(edits, edit{idx(b.Idx0()), idx(list[i+1].Idx0()), ""})
		} else {
			edits = append(edits, edit{idx(list[i-1].Idx1()), idx(b.Idx1()), ""})
		}
	}
	return edits
}

// eatSemicolon extends a removal over the statement's own ';' so deleting
// it doesn't leave an empty statement behind.
func eatSemicolon(src string, e int) int {
	if e < len(src) && src[e] == ';' {
		return e + 1
	}
	return e
}

func identifierUses(prog *ast.Program) map[string]int {
	uses := map[string]int{}
	walk(prog, func(n ast.Node) bool {
		if id, ok := n.(*ast.Identifier); ok {
			uses[id.Name.String()]++
		}
		return true
	})
	return uses
}

func deadForwarder(st ast.Statement, known map[string]bool, uses map[string]int) bool {
	switch s := st.(type) {
	case *ast.FunctionDeclaration:
		if s.Function == nil || s.Function.Name == nil {
			return false
		}
		name := s.Function.Name.Name.String()
		return known[name] && uses[name] == 1
	case *ast.VariableStatement:
		return deadBindings(s.List, known, uses)
	case *ast.LexicalDeclaration:
		return deadBindings(s.List, known, uses)
	}
	return false
}

// deadBindings is true when every binding in a declaration is a resolved
// alias or wrapper that is referenced only by its own declaration.
func deadBindings(list []*ast.Binding, known map[string]bool, uses map[string]int) bool {
	if len(list) == 0 {
		return false
	}
	for _, b := range list {
		id, ok := b.Target.(*ast.Identifier)
		if !ok || !known[id.Name.String()] || uses[id.Name.String()] != 1 {
			return false
		}
	}
	return true
}

// span returns the byte range of a statement, widened to take in any
// parentheses the parser doesn't attribute to it. goja starts an expression
// statement at its first token, so for (function(){...}(arr, 0x8f2a1)) the
// node covers neither the leading "(" nor the trailing ")".
func span(src string, n ast.Node) (int, int) {
	s, e := idx(n.Idx0()), idx(n.Idx1())
	if _, ok := n.(*ast.ExpressionStatement); !ok {
		return s, e
	}
	return widen(src, s, e)
}

// stmtText returns a statement's source, widened like span so it can be
// evaluated on its own.
func stmtText(src string, st ast.Statement) string {
	s, e := idx(st.Idx0()), idx(st.Idx1())
	if _, ok := st.(*ast.ExpressionStatement); ok {
		s, e = widen(src, s, e)
	}
	return src[s:e]
}

// widen grows [s,e) over adjacent '(' / ')' and prefix operators until the
// slice parses on its own, trying the smallest widening first.
func widen(src string, s, e int) (int, int) {
	if src == "" || parses(src[s:e]) {
		return s, e
	}
	var starts []int
	for i := s; i > 0 && len(starts) < 4; {
		i--
		c := src[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c == '(' || c == '!' || c == '~' || c == '+' || c == '-' {
			starts = append(starts, i)
			continue
		}
		break
	}
	var ends []int
	for i := e; i < len(src) && len(ends) < 4; i++ {
		c := src[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c == ')' {
			ends = append(ends, i+1)
			continue
		}
		break
	}
	for _, ns := range append([]int{s}, starts...) {
		for _, ne := range append([]int{e}, ends...) {
			if parses(src[ns:ne]) {
				return ns, ne
			}
		}
	}
	return s, e
}

func parses(code string) bool {
	_, err := parse(code)
	return err == nil
}

// idx converts a goja file.Idx (1-based) to a byte offset.
func idx[T ~int](i T) int { return int(i) - 1 }
