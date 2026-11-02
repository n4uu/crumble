package jsdeob

import (
	"strings"
	"testing"
	"time"
)

// selfDefending has the shape of javascript-obfuscator's self-defending
// decoder after the output has been run through a formatter, which is how
// a current OtterCookie build reached MalwareBazaar. The guard compares
// probe.toString() against compact output; on reformatted code the check
// fails and spin() never returns. Written by hand, no sample code.
const selfDefending = `function a0_arr() {
  const s = ["axios", "http://203.0.113.21:8087/api/notify", "get"];
  a0_arr = function () {
    return s;
  };
  return a0_arr();
}
function a0_dec(i, k) {
  const arr = a0_arr();
  a0_dec = function (j, k2) {
    j = j - 0;
    let v = arr[j];
    if (a0_dec.init === undefined) {
      const Guard = function (fn) {
        this.fn = fn;
        this.state = [1, 0, 0];
        this.probe = function () {
          return "newState";
        };
        this.head = "\\w+ *\\(\\) *{\\w+ *";
        this.tail = "['|\"].+['|\"];? *}";
      };
      Guard.prototype.check = function () {
        const re = new RegExp(this.head + this.tail);
        const n = re.test(this.probe.toString()) ? --this.state[1] : --this.state[0];
        return this.next(n);
      };
      Guard.prototype.next = function (n) {
        if (!Boolean(~n)) {
          return n;
        }
        return this.spin(this.fn);
      };
      Guard.prototype.spin = function (fn) {
        for (let i = 0, len = this.state.length; i < len; i++) {
          this.state.push(Math.round(Math.random()));
          len = this.state.length;
        }
        return fn(this.state[0]);
      };
      new Guard(a0_dec).check();
      a0_dec.init = true;
    }
    return v;
  };
  return a0_dec(i, k);
}
const axios = require(a0_dec(0));
axios[a0_dec(2)](a0_dec(1));
`

func TestSelfDefendingSurvivesReformatting(t *testing.T) {
	start := time.Now()
	res, err := Deobfuscate(selfDefending, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("deobfuscate: %v (after %v)", err, time.Since(start))
	}
	if res.Replaced < 3 {
		t.Errorf("replaced %d call sites, want 3", res.Replaced)
	}
	if !strings.Contains(res.Source, `axios.get('http://203.0.113.21:8087/api/notify')`) {
		t.Errorf("URL not recovered:\n%s", res.Source)
	}
}

// goja ends an expression statement at its last expression's last token,
// so "else a ? b() : (c(), d());" stops before the ")". Folding the dead
// branch used to cut there and leave ");" behind, and every later pass
// worked on text that no longer parsed.
func TestFoldIfKeepsClosingParen(t *testing.T) {
	src := `function f(){if(true){x();}else a?b():(c(),d());}`
	out := simplify(src)
	if !parses(out) {
		t.Fatalf("simplify produced unparsable code: %s", out)
	}
	if out != `function f(){{x();};}` {
		t.Errorf("simplify = %s", out)
	}

	src = `function g(){if(false)y();else z?u():(v(),w());}`
	out = simplify(src)
	if !parses(out) || !strings.Contains(out, "{z?u():(v(),w())}") {
		t.Errorf("simplify = %s", out)
	}
}
