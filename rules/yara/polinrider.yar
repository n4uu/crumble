/*
    PolinRider (DPRK, Contagious Interview) loaders that resolve their next
    step from Ethereum. Written against deobfuscated or plain source: run
    `crumble deobf` first, or scan the base64 variants after decoding.
    Write-up: https://n4uu.github.io/2026/polinrider-tron-to-nullreceiver/
*/

rule PolinRider_NullReceiver_Loader
{
    meta:
        description = "NullReceiver stage 1: C2 read from the recipient of an Ethereum transaction, stages fetched from /0x/cls and /0x/ls"
        author = "n4uu"
        date = "2026-11-21"
        reference = "https://n4uu.github.io/2026/polinrider-tron-to-nullreceiver/#nullreceiver-timed"
    strings:
        $rpc1 = "eth_getBlockByNumber"
        $rpc2 = "eth_blockNumber"
        $p1 = "/0x/cls"
        $p2 = "/0x/ls"
        $h1 = "x-payload-b64" nocase
        $h2 = "'Sec-V'"
        $h3 = "\"Sec-V\""
        $mult = "BLOCK_MULTIPLE"
        $repl = "removeAllListeners(\"end\")"
    condition:
        filesize < 2MB and any of ($rpc*) and all of ($p*) and ($h1 or any of ($h2, $h3)) and ($mult or $repl or $h1)
}

rule PolinRider_EthIndex_BSC_Stage_Loader
{
    meta:
        description = "October 2026 loader: finds a sender on Ethereum by a substring of its address, reads a BSC block number and transaction index from the recipient, decrypts that BSC transaction's input"
        author = "n4uu"
        date = "2026-11-21"
        reference = "https://n4uu.github.io/2026/polinrider-tron-to-nullreceiver/#7-october-tron-out-ethereum-in"
    strings:
        $eth = "eth_getBlockByNumber"
        $bsc1 = "bsc-dataseed.binance.org"
        $bsc2 = "bsc-rpc.publicnode.com"
        $sep = "?.?"
        $inc = "includes"
        // serverKey.substring(2, 10) / ["substring"](2,10): the BSC block number
        $blk = /substring["'\]]{0,2}\(\s*2\s*,\s*10\s*\)/
    condition:
        filesize < 1MB and $eth and any of ($bsc*) and $sep and $inc and $blk
}
