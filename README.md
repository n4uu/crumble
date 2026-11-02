# crumble

[![ci](https://github.com/n4uu/crumble/actions/workflows/ci.yml/badge.svg)](https://github.com/n4uu/crumble/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/n4uu/crumble.svg)](https://pkg.go.dev/github.com/n4uu/crumble)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Config extractor, C2 traffic decoder and detection rules for OtterCookie**,
the Node.js implant behind the Contagious Interview fake job interview
campaign (tracked as WaterPlum by NTT, Famous Chollima by CrowdStrike,
DeceptiveDevelopment by ESET, UNC5342 by GTIG).

It does three things:

1. **`crumble extract`** takes a sample, undoes the javascript-obfuscator
   string array it ships behind, then runs it in a sandbox where every
   Node.js API that touches the outside world is a recording stub. Out comes
   the C2 address the sample actually connects to, the socket.io events it
   listens on and answers with, its check-in fields, and whatever code a
   loader stage tries to `eval`.
2. **`crumble pcap`** rebuilds the socket.io conversation from a packet
   capture: Engine.IO polling handshake, the WebSocket it upgrades to
   (permessage-deflate included), Socket.IO events and binary attachments,
   and a list of the operator's commands with the output that came back.
3. **`rules/`** has YARA and Sigma rules for the shell, loader, collection
   and surveillance modules and for the two delivery tricks that have been
   documented (npm lifecycle scripts and VS Code `folderOpen` tasks). Each
   rule has positive and negative test files and CI fails if one is missing.

Nothing in this repo is malware. The JavaScript under `testdata/` is a set
of inert stubs with the same *shape* as the real modules, run through the
real obfuscator, and the packet capture is generated. All addresses are from
the RFC 5737 documentation ranges or `.invalid`.

## Extracting a config

```
$ crumble extract testdata/js/shell.rc4.obf.js
sample       testdata/js/shell.rc4.obf.js (10965 bytes)
sha256       6dd14413b73f07ae082ad1aef7c00792967cbfb66db792f648d3779e0ce99183
obfuscation  javascript-obfuscator, rc4-encoded string array (61 entries, rotated), 19 wrappers, 0 aliases, 37 calls resolved
verdict      consistent with an OtterCookie socket.io shell module

endpoints
  socket.io C2  http://203.0.113.47:1418  [emulation]

socket.io http://203.0.113.47:1418
  options    reconnectionAttempts=15 reconnectionDelay=2000 timeout=10000
  handlers   connect, command, disconnect
  emits      identify, message
  tasking    "command" -> "message"  (payload echoed back, never reached child_process)
  check-in   "identify" hostname=CRUMBLE-SANDBOX platform=win32 t=5 uid=c7f2a1e09b user=analyst
             (host fields are the sandbox's; ids and constants are the sample's)

roles
  socket.io implant  observed  connects to http://203.0.113.47:1418; operator tasking arrives as "command", results go back as "message"; registers with "identify" on connect

capabilities
  remote shell  static    string "child_process"; string "socket.io-client"

indicators
  url      http://203.0.113.47:1418

modules      child_process, os, socket.io-client
```

That fixture is the hardest javascript-obfuscator preset short of VM
protection: RC4-encoded strings, three layers of chained wrapper functions,
control flow flattening, dead code injection, object key transformation and
self-defending code. Note the `tasking` line. After the sample connects,
crumble hands every custom event handler a probe payload and watches what
happens to it. A real implant forwards it to `child_process.exec` and the
line says so; this fixture only echoes it back, and the line says that too.

Loaders are the other half. Talos documented that since v2 the OtterCookie
loader no longer evals a cookie header: the server answers the token request
with an HTTP error, and the client's error handler passes the error body to
`eval`. `-stage-status 500` reproduces that, `-stage` supplies the body
(a stage you recovered from a capture, or anything you want to watch run):

```
$ crumble extract -stage stage2.js -stage-status 500 testdata/js/loader.rc4.obf.js
...
verdict      consistent with a Contagious Interview loader (remote code delivered in an HTTP response and eval'd)

endpoints
  stage delivery  GET http://api.token-check.invalid:3000/api/service/token/2b8c1d4e  [emulation]

roles
  loader  observed  response from http://api.token-check.invalid:3000/api/service/token/2b8c1d4e was passed to eval

stages
  eval                  23 bytes  sha256 cebfc4a25c61c48679520c2b1e02c438c59a56d269ec831020e7a119a214a5f5
```

The staged code keeps running inside the same sandbox, so a stage that
connects to a socket.io C2 shows up in the same report. `-dump dir/` writes
the deobfuscated source, every staged blob and the raw event trace.

Other flags worth knowing: `-platform all` runs the sample once each as
win32, darwin and linux (OtterCookie branches on `os.platform()` for paths,
clipboard and VM checks), `-root dir/` lets a multi-file npm package
`require()` its own files, `-json` for piping.

## Decoding C2 traffic

```
$ crumble fixture pcap -out demo.pcap      # synthetic, see below
$ crumble pcap demo.pcap
capture: 39 frames, 3 tcp connections, 1 engine.io session(s), 1 other http request(s)

session Gq8vRk2LmZ0aT1xXAAAB  198.51.100.7:51544 -> 203.0.113.47:1418
  engine.io v4 (socket.io 3.x/4.x)  path /socket.io/  transports polling -> websocket  ping 25000/20000 ms
  09:12:03.022 to 09:13:12.341 (1m9.319s), 2 tcp connection(s)
  * server port 1418: OtterCookie socket.io port (Talos)
  * operator sends "command" events and the client answers with "message": the OtterCookie remote shell exchange

  09:12:03.022  <- poll open          {"sid":"Gq8vRk2LmZ0aT1xXAAAB","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":20000,"maxPayload":1000000}
  09:12:03.024  -> poll CONNECT
  09:12:03.030  <- poll CONNECT       {"sid":"Hn3cE0q9_l2oQf7iAAAC"}
  09:12:03.180  -> ws   EVENT         "identify" {"uid":"c7f2a1e09b","t":"5","hostname":"DESKTOP-4F2K9QA","platform":"win32","user":"j.doe"}
  09:12:12.182  <- ws   EVENT         "command" {"message":"whoami"}
  09:12:12.564  -> ws   EVENT         "message" {"uid":"c7f2a1e09b","command":"whoami","result":"desktop-4f2k9qa\\j.doe\r\n"}
  09:12:50.570  <- ws   EVENT         "command" {"message":"dir %USERPROFILE%\\Documents"}
  09:12:50.952  -> ws   EVENT         "message" {"uid":"c7f2a1e09b","command":"dir %USERPROFILE%\\Documents","result":" Volume in drive C has no label.\r\n Directory of C:\\Users\\j.doe\\Documents\r... (1011 bytes)
  09:13:07.955  <- ws   EVENT         "command" {"message":"tasklist /v"}
  09:13:08.337  -> ws   EVENT         "message" {"uid":"c7f2a1e09b","command":"tasklist /v","result":"Image Name                     PID Session Name        Session#    Mem Usage\r\nnode.exe        ... (226 bytes)
  09:13:12.339  -> ws   BINARY_EVENT  "file" {"data":{"_binary":{"bytes":45,"preview":"synthetic attachment: this is not a real key\n","sha256":"364938cb5878ae6a8c30728e74d3bcf5e50957506d122cd93632d... (200 bytes)
  (5 ping/pong/upgrade packets not shown, use -v)

  check-in   "identify" {"uid":"c7f2a1e09b","t":"5","hostname":"DESKTOP-4F2K9QA","platform":"win32","user":"j.doe"}

  operator tasking
    09:12:12.182  command  whoami
                  message  desktop-4f2k9qa\j.doe
    09:12:50.570  command  dir %USERPROFILE%\Documents
                  message   Volume in drive C has no label. |  Directory of C:\Users\j.doe\Documents |  | ... (19 lines)
    09:13:07.955  command  tasklist /v
                  message  Image Name                     PID Session Name        Session#    Mem Usage | node.exe                      6120 Console                    1     48,212 K

other http
  09:13:12.362  198.51.100.7:51561 -> 198.51.100.88:1224  POST http://198.51.100.88:1224/uploads  200  (291 bytes up)
      uploaded files: "Login Data"
      form fields: hid, file
      user-agent: axios/1.7.7
      * path /uploads: BeaverTail/OtterCookie exfiltration path (MITRE S1246, ANY.RUN)
      * port 1224: BeaverTail/InvisibleFerret port
```

The `dir` reply in that capture crossed `ws`'s 1 KiB compression threshold
and went over the wire deflated (RSV1 set). crumble inflates it, with or
without context takeover. The session is stitched together by `sid` across
both TCP connections: the polling requests that did the handshake and the
WebSocket that took over.

`crumble fixture pcap` writes that capture from scratch: real Ethernet/IPv4/
TCP framing with valid checksums, a socket.io-client style handshake and
upgrade, masked client frames. It opens in Wireshark the same as a real one.
Add `-pcapng` for the other container.

## How the extraction works

### Undoing the string array

javascript-obfuscator moves every string literal into one array, rotates
the array by a seed-dependent amount at startup, and replaces each literal
with a call into a decoder, optionally base64 or RC4 encoded. Call sites
don't call the decoder directly: they go through aliases and wrapper
functions that shift the index and reorder arguments, chained several deep.

A lot of public deobfuscators handle this with regexes tuned to one
obfuscator release. crumble parses the script into an AST (goja's parser),
finds the three bootstrap pieces structurally (the array holder, the
function(s) that index into it, the IIFE that rotates it), and evaluates
*just those* in an isolated VM. It then walks the AST for aliases and
wrappers, defines each one in the VM only after proving it's a pure
forwarder (single `return K(...)` whose arguments use nothing but its own
parameters and literals), and evaluates every call site whose arguments are
all constants. That's why rotation, encoding and wrapper layout changes
between obfuscator versions don't matter: the sample's own decoder does the
decoding.

After that come the cleanups that make the output readable and greppable:
`'ht'+'tp:'` chains folded, `obj['key']` to `obj.key`, hex numbers to
decimal, `!![]` to `true`, `'abc' === 'abc'` dead-code guards resolved, and
the per-function proxy objects from control flow flattening inlined
(`_0x1699cc.VBcIe(eval, e.response.data)` becomes `eval(e.response.data)`).
An object is only inlined if every use of it is a read, so one that gets
passed around or mutated is left alone. The bootstrap and every wrapper are
removed once nothing references them.

### Emulation

Strings tell you what's in a sample. Emulation tells you which of them get
used and how. `internal/sandbox` runs the original script (not the
deobfuscated text) in goja with a prelude that replaces `require()`:

| Module | Stub behaviour |
| --- | --- |
| `socket.io-client` | records `io(url, opts)`, every `.on()` and `.emit()`; after the script settles, fires `connect`, then probes each custom event |
| `axios`, `request`, `node-fetch`, `http(s)`, `fetch` | records method, URL, headers, body; answers with the `-stage` body and status |
| `child_process` | records the command, never runs it; recon commands get believable canned output |
| `fs` | reads only from `-root`, records every write and probe |
| `crypto` | real hashes; `createDecipheriv` records algorithm, key and IV |
| `form-data`, `os`, `path`, `Buffer`, `URL`, timers | functional enough to keep samples on their happy path |
| anything else | a recording proxy: every property is another proxy, every call is logged |

`eval`, `new Function` and `new module.constructor()._compile()` are wrapped
so the code passed to them is captured as a stage before it runs. Timers are
virtual: callbacks fire in deadline order without waiting, intervals three
times. A wall-clock budget stops anything that loops.

goja is a pure-Go interpreter. The sample can only reach what the prelude
hands it, and none of that opens a socket, spawns a process, or writes a
file. It is still attacker code running in your process, so treat the
machine like any analysis box. Memory use isn't capped.

### The transport

Engine.IO is the layer under Socket.IO: session handshake, ping/pong, and a
`message` packet type that carries Socket.IO packets. socket.io-client
starts with HTTP long-polling and upgrades to WebSocket; Talos saw exactly
that on port 1418. Two revisions are in the wild and both are decoded:

- **EIO=3** (socket.io 2.x): polling payloads are length-prefixed, and the
  length counts UTF-16 code units, because the reference implementation uses
  JavaScript's `String.length`. A decoder that counts bytes desyncs on the
  first non-ASCII character, which in command output is common. There is
  also a separate binary framing with one byte per decimal digit.
- **EIO=4** (socket.io 3.x and 4.x): packets joined by `0x1e`, binary
  packets base64'd with a `b` prefix.

The capture side is a small dependency-free reader: pcap (both byte orders,
micro and nanosecond), pcapng (EPB, SPB, OPB, `if_tsresol`), Ethernet with
VLAN tags, Linux SLL/SLL2, loopback and raw IP; IPv4 and IPv6 with extension
headers; TCP reassembly that handles out-of-order segments, overlapping
retransmits and sequence wraparound; HTTP/1.1 with chunked bodies and gzip/
deflate content encoding (Engine.IO compresses polling responses over 1 KiB
by default); WebSocket with fragmentation and permessage-deflate. Multipart
uploads are parsed for field and file names, since the collection module
uploads stolen files that way.

## Detection rules

YARA (`rules/yara/ottercookie.yar`):

| Rule | Target | Fires on |
| --- | --- | --- |
| `OtterCookie_SocketIO_Shell` | deobfuscated | socket.io-client + child_process + `.on('command')` + `.emit('message')` |
| `ContagiousInterview_Loader_ErrorHandlerEval` | deobfuscated | HTTP client + `eval(x.response.data)` |
| `OtterCookie_Collector_Strings` | deobfuscated | 2+ wallet extension ids, a browser store, an upload path |
| `OtterCookie_Surveillance_Module` | deobfuscated | `node-global-key-listener` + `screenshot-desktop` + a C2 channel |
| `JavaScriptObfuscator_StringArray_NodeScript` | raw | rotated string array in a Node.js script (hunting) |
| `ContagiousInterview_NPM_Lifecycle_Runs_Fixture` | raw | install lifecycle running an extensionless file under `fixtures/` |
| `ContagiousInterview_VSCode_FolderOpen_Download` | raw | `tasks.json` with `runOn: folderOpen` that downloads and executes |

Most rules target deobfuscated source on purpose. Every literal they would
need is hidden by the string array until it's undone, and a rule written
against the obfuscated form ends up matching the obfuscator, not the
malware. The workflow is `crumble deobf sample.js | yara rules/yara -`,
with the raw structural rule there to pick what to deobfuscate. One
exception falls out of the tests: with `stringArrayEncoding: none` the
array holds plaintext, so `OtterCookie_Surveillance_Module` also fires on
the raw `collector.default` fixture.

Sigma (`rules/sigma/`):

| Rule | Log source | Idea |
| --- | --- | --- |
| Node.js child_process.exec running discovery | process_creation / windows | `node.exe` -> `cmd.exe /d /s /c` (exec's exact wrapping) + recon commands |
| Node.js querying hardware vendor through WMIC | process_creation / windows | v4 VM fingerprinting |
| Node.js shell child reading clipboard or hardware model | process_creation / macos | v5 `pbpaste` polling, hardware model queries a VM check would make |
| Node.js outbound to Contagious Interview C2 ports | network_connection / windows | 1418, 1224, 1244, 1245 to public addresses |
| Engine.IO handshake to raw IP on port 1418 | proxy | `/socket.io/?EIO=` to `a.b.c.d:1418` |
| VS Code task downloading and executing code | process_creation / windows | `Code.exe` -> shell with download piped into an interpreter |
| Node.js executing extensionless file from fixtures | process_creation / windows | the `node test/fixtures/eval` trigger |

`make test-rules` runs every YARA rule against `testdata/rules/expect.json`
(exact match sets, negatives included) and validates the Sigma rules with
pySigma. CI does both.

## Install

```sh
git clone https://github.com/n4uu/crumble
cd crumble
make build                 # needs Go 1.26+
./bin/crumble extract sample.js
./bin/crumble pcap capture.pcapng
```

## Testing

```sh
make test         # Go: deobfuscator, sandbox, extractor, Engine.IO, capture
make test-rules   # YARA positives/negatives + Sigma validation
make fixtures     # regenerate the obfuscated fixtures (needs node)
```

The JavaScript fixtures are real `javascript-obfuscator@4.1.1` output with
fixed seeds, three presets for each of the three module shapes
(`scripts/gen-fixtures.sh`), so the deobfuscator is tested against what the
obfuscator actually emits rather than something written to make a test
pass. The capture tests run the generated session through both pcap and
pcapng, plus hand-built streams for out-of-order delivery, retransmits,
sequence wraparound, chunked+gzip bodies and deflate context takeover.

## Limitations

- **Obfuscation coverage.** The string array transform, wrappers, proxy
  objects and dead-code guards are undone. Control flow flattening is not
  unflattened (the `switch` dispatcher stays), which doesn't affect string
  recovery or emulation but makes `deobf` output harder to read. The
  `mangled` identifier generator reuses short names across scopes and breaks
  the wrapper hoisting; the default `hexadecimal` generator is what samples
  use.
- **Emulation is not Node.** Code that depends on real filesystem state,
  real network responses or native addons will take a different path than
  it would on a victim. Unmodelled APIs return recording proxies, which keeps
  most samples moving but can send a branch somewhere odd. The report marks
  every finding as `observed` (seen during emulation) or `static` (from
  strings only) so you can tell which is which.
- **Attribution.** The verdict line says "consistent with" because
  structure and event names are evidence, not proof. The rules and the
  verdict are based on public reporting (below); they'll need updating as
  the family changes.
- **Encrypted C2.** `crumble pcap` reads cleartext HTTP and WebSocket.
  Sessions over TLS need keys or a decrypted capture first.

## References

- Cisco Talos, [BeaverTail and OtterCookie evolve with a new JavaScript module](https://blog.talosintelligence.com/beavertail-and-ottercookie/) (socket.io on 1418, error-handler loader, v5 keylogger/screenshot module, node-nvm-ssh trigger)
- NTT Security, [OtterCookie, a new malware used in Contagious Interview campaign](https://jp.security.ntt/tech_blog/en-contagious-interview-ottercookie) and [WaterPlum's OtterCookie v3/v4](https://jp.security.ntt/tech_blog/en-waterplum-ottercookie)
- Elastic Security Labs, [New North Korean campaign uses fake coding interviews to steal developer credentials](https://www.elastic.co/security-labs/threat-command/contagious-interview-malware-svg-steganography) (`command`/`message` exchange, `/upload` and `/cldbs` endpoints, VM check behaviour)
- Microsoft, [Contagious Interview: malware delivered through fake developer job interviews](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/)
- MITRE ATT&CK, [BeaverTail (S1246)](https://attack.mitre.org/software/S1246/)
- ANY.RUN, [InvisibleFerret technical analysis](https://anyrun.substack.com/p/invisibleferret-malware-technical) (`/pdown`, `/keys`, ports 1244/1245)
- Protocol specs: [engine.io-protocol](https://github.com/socketio/engine.io-protocol), [socket.io-protocol](https://github.com/socketio/socket.io-protocol), [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455), [RFC 7692](https://www.rfc-editor.org/rfc/rfc7692)

See also [prowl](https://github.com/n4uu/prowl), which hunts the
infrastructure side of the same campaign.

## License

MIT, see [LICENSE](LICENSE).
