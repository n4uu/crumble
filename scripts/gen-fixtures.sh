#!/usr/bin/env bash
# Regenerates testdata/js/*.obf.js from testdata/js/src with a pinned
# javascript-obfuscator and fixed seeds, so the deobfuscator is always tested
# against real obfuscator output rather than something hand-written to pass.
#
#   default  string array + rotation + shuffle, no encoding, 1 variable wrapper
#   b64      base64-encoded array, 2 function wrappers, index shift, split strings
#   rc4      rc4-encoded array, 3 function wrappers with 5 params, control flow
#            flattening, dead code, object key transform, self-defending
#
# Requires node/npx. Output is committed; CI does not run this.
set -euo pipefail

cd "$(dirname "$0")/../testdata/js"
OBF="${OBF:-npx --yes javascript-obfuscator@4.1.1}"

common=(--target node --seed 1337 --compact true --string-array true
        --string-array-rotate true --string-array-shuffle true --string-array-threshold 1)

for f in src/*.js; do
  name=$(basename "$f" .js)

  $OBF "$f" --output "$name.default.obf.js" "${common[@]}" \
    --string-array-encoding none \
    --string-array-wrappers-count 1 --string-array-wrappers-type variable

  $OBF "$f" --output "$name.b64.obf.js" "${common[@]}" \
    --string-array-encoding base64 --string-array-index-shift true \
    --string-array-wrappers-count 2 --string-array-wrappers-type function \
    --split-strings true --split-strings-chunk-length 4

  $OBF "$f" --output "$name.rc4.obf.js" "${common[@]}" \
    --string-array-encoding rc4 --string-array-index-shift true \
    --string-array-wrappers-count 3 --string-array-wrappers-type function \
    --string-array-wrappers-parameters-max-count 5 --string-array-wrappers-chained-calls true \
    --control-flow-flattening true --control-flow-flattening-threshold 1 \
    --dead-code-injection true --dead-code-injection-threshold 0.4 \
    --transform-object-keys true --self-defending true
done

# The YARA positives are the deobfuscated output of two presets per module.
cd ../..
for name in shell loader collector; do
  for preset in default rc4; do
    go run ./cmd/crumble deobf "testdata/js/$name.$preset.obf.js" 2>/dev/null \
      > "testdata/rules/pos/$name.$preset.deobf.js"
  done
done
