// Package jsenv prepares a goja runtime for running obfuscated samples.
//
// javascript-obfuscator's self-defending option plants checks that read a
// function's own source with Function.prototype.toString and compare it
// against what compact output looks like. If the code has been reformatted
// (which is how a lot of samples reach MalwareBazaar or a victim's repo)
// the checks either spin in an endless loop or run a regex with nested
// quantifiers, "(((.+)+)+)+$", that backtracks exponentially on multi-line
// text. Both kill emulation, and the regex case can't even be interrupted
// because it runs inside the regex engine, not the VM.
//
// Install makes toString return the source with line breaks and their
// indentation removed, so a reformatted sample takes the same path it
// would have taken compact. As a backstop every regex match is given a
// time limit; a match that hits it throws a RangeError in the sample
// instead of hanging the process.
package jsenv

import (
	"time"

	"github.com/dlclark/regexp2/v2"
	"github.com/dop251/goja"
)

// RegexpTimeout bounds a single regex match. It is read when a pattern is
// compiled.
const RegexpTimeout = 2 * time.Second

func init() {
	// goja compiles every pattern with regexp2, which takes its match
	// timeout from this package variable.
	regexp2.DefaultMatchTimeout = RegexpTimeout
}

// compactToString replaces Function.prototype.toString. A line break and
// the whitespace around it are dropped, or turned into one space when both
// neighbours are identifier characters, so "{\n  return x;\n}" becomes
// "{return x;}" and "let a\nlet b" stays two statements.
const compactToString = `(function () {
  "use strict";
  const proto = Function.prototype;
  const real = proto.toString;
  const word = /[\w$]/;
  function compact(s) {
    return s.replace(/[ \t]*(?:\r\n|\r|\n)\s*/g, function (m, off, all) {
      return word.test(all.charAt(off - 1)) && word.test(all.charAt(off + m.length)) ? " " : "";
    });
  }
  const toString = { toString() { return compact(real.call(this)); } }.toString;
  Object.defineProperty(proto, "toString", { value: toString, writable: true, enumerable: false, configurable: true });
})();`

// MaxCallStack is roughly where Node throws "Maximum call stack size
// exceeded" with default flags. goja has no limit unless one is set, so
// unbounded recursion would eat memory until the budget ran out. Unlike
// Node's, goja's overflow error can't be caught by the sample; it ends the
// run.
const MaxCallStack = 10000

// Install patches vm. Call it before running any sample code.
func Install(vm *goja.Runtime) error {
	vm.SetMaxCallStackSize(MaxCallStack)
	_, err := vm.RunString(compactToString)
	return err
}
