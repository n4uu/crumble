/*
   OtterCookie / Contagious Interview detection rules.

   Most rules here target source that has been run through `crumble deobf`
   (or a sample that was never obfuscated). Every OtterCookie build seen so
   far ships behind javascript-obfuscator's string array, which hides every
   literal these rules look for until it's undone. Scanning raw samples only
   makes sense for the two structural rules marked "raw".

   Positive and negative test files: testdata/rules/, run with
   `make test-rules`.
*/

rule OtterCookie_SocketIO_Shell
{
    meta:
        description = "OtterCookie socket.io remote shell module: receives 'command' events and answers with 'message'"
        author = "n4uu"
        date = "2026-11-02"
        reference = "https://blog.talosintelligence.com/beavertail-and-ottercookie/"
        target = "deobfuscated"
        score = 80

    strings:
        $sio = "socket.io-client" ascii
        $cp = "child_process" ascii
        $on_cmd = /\.on\(\s*['"]command['"]\s*,/ ascii
        $emit_msg = /\.emit\(\s*['"]message['"]\s*,/ ascii

    condition:
        filesize < 2MB and $sio and $cp and $on_cmd and $emit_msg
}

rule ContagiousInterview_Loader_ErrorHandlerEval
{
    meta:
        description = "Loader that requests a token URL and evals the HTTP error body (OtterCookie v2+ / BeaverTail delivery)"
        author = "n4uu"
        date = "2026-11-02"
        reference = "https://blog.talosintelligence.com/beavertail-and-ottercookie/"
        target = "deobfuscated"
        score = 75

    strings:
        $http = /require\(\s*['"](axios|request|node-fetch)['"]\s*\)/ ascii
        $eval_err = /eval\(\s*[\w$]{1,40}\.response\.data\s*\)/ ascii

    condition:
        filesize < 2MB and $http and $eval_err
}

rule OtterCookie_Collector_Strings
{
    meta:
        description = "OtterCookie v4/v5 collection module: wallet extension ids, browser stores, and an upload path in one Node.js file"
        author = "n4uu"
        date = "2026-11-02"
        reference = "https://www.elastic.co/security-labs/threat-command/contagious-interview-malware-svg-steganography"
        target = "deobfuscated"
        score = 70

    strings:
        $w1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii // MetaMask
        $w2 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii // Phantom
        $w3 = "hnfanknocfeofbddgcijnmhnfnkdnaad" ascii // Coinbase Wallet
        $w4 = "ibnejdfjmmkpcnlpebklmnkoeoihofec" ascii // TronLink
        $w5 = "fhbohimaelbohpjbbldcngcnapndodjp" ascii // Binance Wallet
        $b1 = "Login Data" ascii
        $b2 = "Local Extension Settings" ascii
        $b3 = "Local State" ascii
        $u1 = "/uploads" ascii
        $u2 = "/upload" ascii
        $u3 = "/cldbs" ascii
        $u4 = "form-data" ascii
        $req = "require(" ascii

    condition:
        filesize < 2MB and $req and 2 of ($w*) and 1 of ($b*) and 1 of ($u*)
}

rule OtterCookie_Surveillance_Module
{
    meta:
        description = "OtterCookie v5 keylogger/screenshot module: both npm packages Talos reported, plus a C2 channel"
        author = "n4uu"
        date = "2026-11-02"
        reference = "https://blog.talosintelligence.com/beavertail-and-ottercookie/"
        target = "deobfuscated"
        score = 70

    strings:
        $k = "node-global-key-listener" ascii
        $s = "screenshot-desktop" ascii
        $c1 = "socket.io-client" ascii
        $c2 = "form-data" ascii
        $c3 = "/upload" ascii

    condition:
        filesize < 2MB and $k and $s and 1 of ($c*)
}

rule JavaScriptObfuscator_StringArray_NodeScript
{
    meta:
        description = "Hunting: Node.js script protected with javascript-obfuscator's rotated string array. Not malicious on its own; triage hits with `crumble deobf` and rescan"
        author = "n4uu"
        date = "2026-11-02"
        target = "raw"
        score = 30

    strings:
        $rotate = /\[['"]push['"]\]\(\s*[\w$]{1,12}\[['"]shift['"]\]\(\)\s*\)/ ascii
        $loop = "while(!![])" ascii
        $parse = "parseInt(" ascii
        $hex_id = /_0x[0-9a-f]{4,6}\(0x[0-9a-f]{1,4}/ ascii
        $require = "require(" ascii

    condition:
        filesize < 5MB and $rotate and $loop and $parse and #hex_id > 5 and $require
}

rule ContagiousInterview_NPM_Lifecycle_Runs_Fixture
{
    meta:
        description = "Hunting: package.json whose install lifecycle runs node against an extensionless file under fixtures/, the trigger Talos documented in the node-nvm-ssh package ('npm run skip' -> node test/fixtures/eval)"
        author = "n4uu"
        date = "2026-11-02"
        reference = "https://blog.talosintelligence.com/beavertail-and-ottercookie/"
        target = "raw"
        score = 50

    strings:
        $scripts = "\"scripts\"" ascii
        $lifecycle = /"(preinstall|install|postinstall|prepare|prepublish)"\s*:\s*"[^"]{0,80}(npm run|node )/ ascii
        // extensionless file under fixtures/: running a .js test runner is
        // normal, executing something that looks like test data is not
        $fixture = /"\s*:\s*"node\s+(\.\/)?[\w\/-]{0,40}fixtures?\/[\w\/-]{1,60}"/ ascii

    condition:
        filesize < 64KB and $scripts and $lifecycle and $fixture
}

rule ContagiousInterview_VSCode_FolderOpen_Download
{
    meta:
        description = "Hunting: .vscode/tasks.json that runs a download-and-execute command as soon as the folder is opened"
        author = "n4uu"
        date = "2026-11-02"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/"
        target = "raw"
        score = 60

    strings:
        $run_on = /"runOn"\s*:\s*"folderOpen"/ ascii
        $fetch = /(curl|wget|Invoke-WebRequest|iwr|irm|Invoke-RestMethod)\b/ ascii nocase
        $exec1 = /\|\s*(sh|bash|zsh|node|iex|powershell)\b/ ascii nocase
        $exec2 = /node\s+-e\b/ ascii
        $exec3 = "IEX(" ascii nocase

    condition:
        filesize < 64KB and $run_on and $fetch and 1 of ($exec*)
}
