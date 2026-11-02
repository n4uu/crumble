package jsdeob

import (
	"reflect"

	"github.com/dop251/goja/ast"
)

var nodeType = reflect.TypeOf((*ast.Node)(nil)).Elem()

// walk visits every ast.Node reachable from n in source order. If fn returns
// false the children of that node are skipped.
//
// goja doesn't ship a visitor, and hand-writing a type switch over ~70 node
// types is how you end up silently skipping one, so this walks the struct
// fields with reflection instead. Two fields are deliberately ignored:
// FunctionLiteral.DeclarationList is the parser's hoisting bookkeeping and
// points back into nodes we already visit through the statement list, and
// Source is just a string copy of the function text.
func walk(n any, fn func(ast.Node) bool) {
	walkValue(reflect.ValueOf(n), fn)
}

func walkValue(v reflect.Value, fn func(ast.Node) bool) {
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return
		}
		walkValue(v.Elem(), fn)
		return
	case reflect.Ptr:
		if v.IsNil() {
			return
		}
		if v.Type().Implements(nodeType) {
			if !fn(v.Interface().(ast.Node)) {
				return
			}
		}
		walkValue(v.Elem(), fn)
		return
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			walkValue(v.Index(i), fn)
		}
		return
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() || f.Name == "DeclarationList" || f.Name == "Source" {
				continue
			}
			fv := v.Field(i)
			// Embedded value structs (OptionalChain, SpreadElement, ...) and
			// value-typed Identifier fields (DotExpression.Identifier) carry
			// no children we care about beyond what Elem() already exposes,
			// but a struct-valued field can still hold nested nodes.
			if fv.Kind() == reflect.Struct && fv.CanAddr() && fv.Addr().Type().Implements(nodeType) {
				walkValue(fv.Addr(), fn)
				continue
			}
			walkValue(fv, fn)
		}
	}
}

// statementLists returns every statement list in the program: the top level,
// every block, and every switch case body. The string array bootstrap is
// normally at the top level, but bundlers and some obfuscator presets wrap
// the whole file in an IIFE, so it can sit one or more blocks down.
func statementLists(prog *ast.Program) [][]ast.Statement {
	lists := [][]ast.Statement{prog.Body}
	walk(prog, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.BlockStatement:
			lists = append(lists, s.List)
		case *ast.CaseStatement:
			lists = append(lists, s.Consequent)
		}
		return true
	})
	return lists
}
