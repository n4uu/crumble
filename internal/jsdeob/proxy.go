package jsdeob

import (
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/token"
)

// Control flow flattening and dead code injection both route expressions
// through per-function "proxy" objects:
//
//	const _0x1699cc = {'KKLIH': '(((.+)+)+)+$',
//	                   'ILgqM': function(a, b) { return a + b; },
//	                   'VBcIe': function(f, x) { return f(x); }};
//	... _0x1699cc.VBcIe(eval, err.response.data) ...
//
// transformObjectKeys additionally splits the literal into
// `const o = {}; o.k1 = 'v1', o.k2 = 'v2';`. inlineProxies folds both forms
// back so the call above reads eval(err.response.data) again, which matters
// for anyone grepping (or YARA-scanning) the output for eval(.
//
// An object is only treated as a proxy if every use of its name is a
// declaration, a `.key =` store of a literal, an alias, or a `.key` read.
// Anything else (passed to a function, iterated, deleted from) disqualifies
// it, because then we can't be sure the values we inline are the ones it
// holds at the read site.

type proxyValue struct {
	str  *string
	op   token.Token // binary/logical operator template: return p0 OP p1
	call bool        // call template: return p0(p1, p2, ...)
}

type proxyObj struct {
	props   map[string]proxyValue
	aliases []string
	bad     bool
}

func inlineProxies(src string) string {
	prog, err := parse(src)
	if err != nil {
		return src
	}

	objs := map[string]*proxyObj{}
	alias := map[string]string{} // alias name -> proxy name

	// Pass 1: declarations.
	walk(prog, func(n ast.Node) bool {
		b, ok := n.(*ast.Binding)
		if !ok {
			return true
		}
		id, ok := b.Target.(*ast.Identifier)
		if !ok {
			return true
		}
		name := id.Name.String()
		switch init := b.Initializer.(type) {
		case *ast.ObjectLiteral:
			if p := proxyFromLiteral(init); p != nil {
				if _, dup := objs[name]; dup {
					objs[name].bad = true // shadowed name, give up on it
				} else {
					objs[name] = p
				}
			}
		case *ast.Identifier:
			alias[name] = init.Name.String()
		}
		return true
	})
	for a, target := range alias {
		if p, ok := objs[target]; ok {
			p.aliases = append(p.aliases, a)
		} else {
			delete(alias, a)
		}
	}
	resolve := func(name string) (*proxyObj, bool) {
		if p, ok := objs[name]; ok {
			return p, true
		}
		if t, ok := alias[name]; ok {
			return objs[t], true
		}
		return nil, false
	}

	// Pass 2: stores of the split form, and anything that disqualifies.
	allowed := map[*ast.Identifier]bool{}
	walk(prog, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Binding:
			if id, ok := x.Target.(*ast.Identifier); ok {
				allowed[id] = true
			}
			if id, ok := x.Initializer.(*ast.Identifier); ok {
				if _, isProxy := resolve(id.Name.String()); isProxy {
					allowed[id] = true
				}
			}
		case *ast.AssignExpression:
			key, obj, ok := memberKey(x.Left)
			if !ok {
				return true
			}
			p, isProxy := resolve(obj.Name.String())
			if !isProxy {
				return true
			}
			allowed[obj] = true
			if x.Operator != token.ASSIGN {
				p.bad = true
				return true
			}
			if lit, ok := x.Right.(*ast.StringLiteral); ok {
				if _, exists := p.props[key]; exists {
					p.bad = true // assigned twice, value depends on position
				}
				v := lit.Value.String()
				p.props[key] = proxyValue{str: &v}
			} else {
				p.bad = true
			}
		case *ast.DotExpression, *ast.BracketExpression:
			if d, ok := x.(*ast.DotExpression); ok {
				allowed[&d.Identifier] = true // property name, not a variable
			}
			if _, obj, ok := memberKey(x.(ast.Expression)); ok {
				if _, isProxy := resolve(obj.Name.String()); isProxy {
					allowed[obj] = true
				}
			}
		}
		return true
	})
	walk(prog, func(n ast.Node) bool {
		id, ok := n.(*ast.Identifier)
		if !ok || allowed[id] {
			return true
		}
		if p, isProxy := resolve(id.Name.String()); isProxy {
			p.bad = true
		}
		return true
	})

	// Pass 3: rewrite reads and calls.
	var edits []edit
	walk(prog, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignExpression:
			if _, obj, ok := memberKey(x.Left); ok {
				if p, isProxy := resolve(obj.Name.String()); isProxy && !p.bad {
					return false // a store; the target isn't a read
				}
			}
		case *ast.CallExpression:
			key, obj, ok := memberKey(x.Callee)
			if !ok {
				return true
			}
			p, isProxy := resolve(obj.Name.String())
			if !isProxy || p.bad {
				return true
			}
			v, ok := p.props[key]
			if !ok {
				return true
			}
			args := make([]string, len(x.ArgumentList))
			for i, a := range x.ArgumentList {
				args[i] = src[idx(a.Idx0()):idx(a.Idx1())]
				if strings.HasPrefix(strings.TrimSpace(src[idx(a.Idx1()):]), "...") {
					return true
				}
			}
			var text string
			switch {
			case v.op != 0 && len(args) == 2:
				text = "(" + args[0] + " " + v.op.String() + " " + args[1] + ")"
			case v.call && len(args) >= 1:
				text = args[0] + "(" + strings.Join(args[1:], ", ") + ")"
			default:
				return true
			}
			// Arguments can themselves contain proxy calls; leave those for
			// the next pass rather than splicing overlapping edits.
			edits = append(edits, edit{idx(x.Idx0()), idx(x.Idx1()), text})
			return false
		case *ast.DotExpression, *ast.BracketExpression:
			key, obj, ok := memberKey(x.(ast.Expression))
			if !ok {
				return true
			}
			p, isProxy := resolve(obj.Name.String())
			if !isProxy || p.bad {
				return true
			}
			if v, ok := p.props[key]; ok && v.str != nil {
				edits = append(edits, edit{idx(x.Idx0()), idx(x.Idx1()), quote(*v.str)})
			}
			return false
		}
		return true
	})
	if len(edits) > 0 {
		return apply(src, edits)
	}
	return removeDeadProxies(src, prog, objs, alias)
}

// removeDeadProxies deletes proxy objects (and their aliases and split-form
// stores) once inlining has removed every read.
func removeDeadProxies(src string, prog *ast.Program, objs map[string]*proxyObj, alias map[string]string) string {
	// Everything that isn't a declaration target, an alias initialiser or the
	// object of a `.key =` store counts as a read.
	notRead := map[*ast.Identifier]bool{}
	walk(prog, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Binding:
			if id, ok := x.Target.(*ast.Identifier); ok {
				notRead[id] = true
			}
			if id, ok := x.Initializer.(*ast.Identifier); ok {
				notRead[id] = true
			}
		case *ast.AssignExpression:
			if _, obj, ok := memberKey(x.Left); ok {
				notRead[obj] = true
			}
		case *ast.DotExpression:
			notRead[&x.Identifier] = true // property name, not a variable
		}
		return true
	})
	reads := map[string]int{}
	walk(prog, func(n ast.Node) bool {
		if id, ok := n.(*ast.Identifier); ok && !notRead[id] {
			reads[id.Name.String()]++
		}
		return true
	})

	dead := map[string]bool{}
	for name, p := range objs {
		if p.bad || reads[name] > 0 {
			continue
		}
		ok := true
		for _, a := range p.aliases {
			if reads[a] > 0 {
				ok = false
			}
		}
		if !ok {
			continue
		}
		dead[name] = true
		for _, a := range p.aliases {
			dead[a] = true
		}
	}
	if len(dead) == 0 {
		return src
	}

	var edits []edit
	for _, list := range statementLists(prog) {
		for _, st := range list {
			switch s := st.(type) {
			case *ast.VariableStatement, *ast.LexicalDeclaration:
				edits = append(edits, removeBindings(src, s, func(name string) bool { return dead[name] })...)
			case *ast.ExpressionStatement:
				if storesOnly(s.Expression, dead) {
					st, e := span(src, s)
					edits = append(edits, edit{st, eatSemicolon(src, e), ""})
				}
			}
		}
	}
	return apply(src, edits)
}

// storesOnly is true for `o.a = 'x', o.b = 'y'` where every target is dead.
func storesOnly(e ast.Expression, dead map[string]bool) bool {
	var parts []ast.Expression
	if seq, ok := e.(*ast.SequenceExpression); ok {
		parts = seq.Sequence
	} else {
		parts = []ast.Expression{e}
	}
	for _, p := range parts {
		as, ok := p.(*ast.AssignExpression)
		if !ok {
			return false
		}
		_, obj, ok := memberKey(as.Left)
		if !ok || !dead[obj.Name.String()] {
			return false
		}
		if _, ok := as.Right.(*ast.StringLiteral); !ok {
			return false
		}
	}
	return true
}

// memberKey splits o.k / o['k'] into ("k", o).
func memberKey(e ast.Expression) (string, *ast.Identifier, bool) {
	switch m := e.(type) {
	case *ast.DotExpression:
		if id, ok := m.Left.(*ast.Identifier); ok {
			return m.Identifier.Name.String(), id, true
		}
	case *ast.BracketExpression:
		id, ok := m.Left.(*ast.Identifier)
		if !ok {
			return "", nil, false
		}
		if lit, ok := m.Member.(*ast.StringLiteral); ok {
			return lit.Value.String(), id, true
		}
	}
	return "", nil, false
}

func proxyFromLiteral(o *ast.ObjectLiteral) *proxyObj {
	p := &proxyObj{props: map[string]proxyValue{}}
	for _, prop := range o.Value {
		kp, ok := prop.(*ast.PropertyKeyed)
		if !ok || kp.Computed || kp.Kind != ast.PropertyKindValue {
			return nil
		}
		var key string
		switch k := kp.Key.(type) {
		case *ast.StringLiteral:
			key = k.Value.String()
		case *ast.Identifier:
			key = k.Name.String()
		default:
			return nil
		}
		switch v := kp.Value.(type) {
		case *ast.StringLiteral:
			s := v.Value.String()
			p.props[key] = proxyValue{str: &s}
		case *ast.FunctionLiteral:
			pv, ok := proxyTemplate(v)
			if !ok {
				return nil
			}
			p.props[key] = pv
		default:
			return nil
		}
	}
	return p
}

// proxyTemplate matches function(a,b){return a OP b} and
// function(f,a,b,...){return f(a,b,...)} with parameters used in order.
func proxyTemplate(fn *ast.FunctionLiteral) (proxyValue, bool) {
	if fn.Body == nil || len(fn.Body.List) != 1 || fn.ParameterList == nil || fn.ParameterList.Rest != nil {
		return proxyValue{}, false
	}
	ret, ok := fn.Body.List[0].(*ast.ReturnStatement)
	if !ok || ret.Argument == nil {
		return proxyValue{}, false
	}
	var ps []string
	for _, b := range fn.ParameterList.List {
		id, ok := b.Target.(*ast.Identifier)
		if !ok || b.Initializer != nil {
			return proxyValue{}, false
		}
		ps = append(ps, id.Name.String())
	}
	isParam := func(e ast.Expression, i int) bool {
		id, ok := e.(*ast.Identifier)
		return ok && i < len(ps) && id.Name.String() == ps[i]
	}
	switch r := ret.Argument.(type) {
	case *ast.BinaryExpression:
		if len(ps) == 2 && isParam(r.Left, 0) && isParam(r.Right, 1) {
			return proxyValue{op: r.Operator}, true
		}
	case *ast.CallExpression:
		if len(ps) >= 1 && isParam(r.Callee, 0) && len(r.ArgumentList) == len(ps)-1 {
			for i, a := range r.ArgumentList {
				if !isParam(a, i+1) {
					return proxyValue{}, false
				}
			}
			return proxyValue{call: true}, true
		}
	}
	return proxyValue{}, false
}
