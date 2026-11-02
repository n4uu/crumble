// Command crumble pulls C2 configuration out of OtterCookie (Contagious
// Interview / WaterPlum) JavaScript samples and reconstructs their
// socket.io C2 conversations from packet captures.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/n4uu/crumble/internal/capture"
	"github.com/n4uu/crumble/internal/extract"
	"github.com/n4uu/crumble/internal/fixture"
	"github.com/n4uu/crumble/internal/jsdeob"
	"github.com/n4uu/crumble/internal/sandbox"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "extract", "x":
		err = runExtract(os.Args[2:])
	case "deobf", "d":
		err = runDeobf(os.Args[2:])
	case "pcap", "p":
		err = runPcap(os.Args[2:])
	case "fixture":
		err = runFixture(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Printf("crumble %s\n", version)
		return
	case "help", "-h", "-help", "--help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "crumble: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `crumble: OtterCookie config extractor and socket.io C2 decoder

usage:
  crumble extract [flags] <sample.js>...   deobfuscate + emulate a sample, print its C2 config
  crumble deobf [flags] <sample.js>        print the sample with its string array resolved
  crumble pcap [flags] <capture>           rebuild Engine.IO / Socket.IO C2 sessions from a pcap or pcapng
  crumble fixture pcap -out <file>         write a synthetic C2 capture to try "crumble pcap" on
  crumble version

run "crumble <command> -h" for flags.
`)
}

func runExtract(args []string) error {
	fs := flag.NewFlagSet("extract", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	platform := fs.String("platform", "win32", `platform(s) to emulate: win32, darwin, linux, comma-separated, or "all"`)
	root := fs.String("root", "", "directory the sample may require()/read files from (for multi-file packages)")
	stage := fs.String("stage", "", "file to serve as the body of every HTTP response (e.g. a captured stage 2)")
	status := fs.Int("stage-status", 200, "HTTP status for -stage; >= 400 reproduces loaders that eval the error body")
	noEmu := fs.Bool("no-emulate", false, "static analysis only")
	dump := fs.String("dump", "", "write the deobfuscated source, staged code and raw trace to this directory")
	budget := fs.Duration("budget", 5*time.Second, "wall-clock budget per emulation run")
	fs.Parse(args)
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: crumble extract [flags] <sample.js>...")
	}

	plats := strings.Split(*platform, ",")
	if *platform == "all" {
		plats = []string{"win32", "darwin", "linux"}
	}
	resp := sandbox.Response{Status: *status}
	if *stage != "" {
		b, err := os.ReadFile(*stage)
		if err != nil {
			return err
		}
		resp.Body = string(b)
	}

	var reports []*extract.Report
	for _, path := range fs.Args() {
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rep, err := extract.Extract(src, extract.Options{
			Name: path, Platforms: plats, Root: *root, Response: resp,
			NoEmulate: *noEmu, Budget: *budget,
		})
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if *dump != "" {
			if err := dumpReport(*dump, rep); err != nil {
				return err
			}
		}
		reports = append(reports, rep)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if len(reports) == 1 {
			return enc.Encode(reports[0])
		}
		return enc.Encode(reports)
	}
	for i, r := range reports {
		if i > 0 {
			fmt.Println(strings.Repeat("-", 72))
		}
		fmt.Print(extract.RenderText(r))
	}
	return nil
}

func dumpReport(dir string, r *extract.Report) error {
	base := filepath.Join(dir, r.SHA256[:16])
	if err := os.MkdirAll(base, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(base, "deobfuscated.js"), []byte(r.Deobfuscated), 0o644); err != nil {
		return err
	}
	for i, s := range r.Stages {
		name := fmt.Sprintf("stage%02d_%s.js", i, sanitize(s.Via))
		if err := os.WriteFile(filepath.Join(base, name), []byte(s.Code), 0o644); err != nil {
			return err
		}
	}
	if r.Trace != nil {
		b, _ := json.MarshalIndent(r.Trace, "", "  ")
		if err := os.WriteFile(filepath.Join(base, "trace.json"), b, 0o644); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", base)
	return nil
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '_'
	}, s)
}

func runDeobf(args []string) error {
	fs := flag.NewFlagSet("deobf", flag.ExitOnError)
	keep := fs.Bool("keep-bootstrap", false, "leave the string array, decoder and rotation code in the output")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: crumble deobf [-keep-bootstrap] <sample.js>")
	}
	src, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	res, err := jsdeob.Deobfuscate(string(src), jsdeob.Options{KeepBootstrap: *keep})
	if res == nil {
		return err
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "%s encoding, %d strings, %d wrappers, %d aliases, %d calls resolved, %d failed\n",
			res.Encoding, res.ArraySize, res.Wrappers, res.Aliases, res.Replaced, res.Failed)
	}
	fmt.Println(res.Source)
	return nil
}

func runPcap(args []string) error {
	fs := flag.NewFlagSet("pcap", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	verbose := fs.Bool("v", false, "include ping/pong and upgrade packets in the timeline")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: crumble pcap [-json] [-v] <capture.pcap|pcapng>")
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()
	frames, err := capture.ReadAll(f)
	if err != nil {
		return err
	}
	a := capture.Analyze(frames)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(a)
	}
	fmt.Print(capture.RenderText(a, *verbose))
	if len(a.Sessions) == 0 && len(a.HTTP) == 0 {
		return fmt.Errorf("no HTTP or Engine.IO traffic found (TLS-wrapped C2 can't be decoded from a capture alone)")
	}
	return nil
}

func runFixture(args []string) error {
	if len(args) == 0 || args[0] != "pcap" {
		return fmt.Errorf("usage: crumble fixture pcap [-pcapng] -out <file>")
	}
	fs := flag.NewFlagSet("fixture pcap", flag.ExitOnError)
	out := fs.String("out", "", "output file (required)")
	ng := fs.Bool("pcapng", false, "write pcapng instead of pcap")
	fs.Parse(args[1:])
	if *out == "" {
		return fmt.Errorf("usage: crumble fixture pcap [-pcapng] -out <file>")
	}
	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	format := fixture.Pcap
	if *ng {
		format = fixture.Pcapng
	}
	if err := fixture.Write(f, fixture.DefaultScenario(), format); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s: a synthetic socket.io C2 session between RFC 5737 documentation addresses.\n", *out)
	fmt.Fprintf(os.Stderr, "no real traffic, nothing malicious; it exists so \"crumble pcap\" has something to decode.\n")
	return nil
}
