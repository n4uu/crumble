#!/bin/sh
# Run rules/suricata against the synthetic captures and check alert counts.
set -eu
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
python3 "$(dirname "$0")/gen_suricata_pcaps.py" "$dir/pos.pcap" "$dir/neg.pcap" >/dev/null
count() {
    mkdir -p "$dir/$1"
    suricata -r "$dir/$1.pcap" -S rules/suricata/contagious_interview.rules -k none -l "$dir/$1" \
        --set vars.address-groups.HOME_NET="[192.0.2.0/24]" \
        --set vars.address-groups.EXTERNAL_NET='!$HOME_NET' >/dev/null 2>&1
    wc -l < "$dir/$1/fast.log" | tr -d ' '
}
pos=$(count pos)
neg=$(count neg)
echo "positive capture: $pos alerts (want 2), negative capture: $neg alerts (want 0)"
[ "$pos" = 2 ] && [ "$neg" = 0 ]
