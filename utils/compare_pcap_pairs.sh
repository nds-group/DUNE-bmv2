#!/usr/bin/env bash

PCAP_DIR="../pcaps"

# Extract packet counts with capinfos
declare -A counts

while IFS=$'\t' read -r file pkts; do
    fname=$(basename "$file")
    counts["$fname"]=$pkts
done < <(capinfos -T -c -r "$PCAP_DIR"/*.pcap )

echo "Comparing pcap pairs in $PCAP_DIR"
echo "--------------------------------"

for f in "$PCAP_DIR"/*-eth2_in.pcap; do
    [ -s "$f" ] || continue   # skip zero-size files
    base=$(basename "$f" -eth2_in.pcap)
    p1=$(basename "$f")

    # matching partner
    partner="$PCAP_DIR/${base}-eth1_out.pcap"
    if [ -s "$partner" ]; then
        p2=$(basename "$partner")
        c1=${counts[$p1]:-0}
        c2=${counts[$p2]:-0}
        echo "Pair: $p1 ↔ $p2 | pkts: $c1 vs $c2 | diff=$((c1-c2))"
    fi
done

for f in "$PCAP_DIR"/*-eth1_in.pcap; do
    [ -s "$f" ] || continue
    base=$(basename "$f" -eth1_in.pcap)
    p1=$(basename "$f")

    partner="$PCAP_DIR/${base}-eth2_out.pcap"
    if [ -s "$partner" ]; then
        p2=$(basename "$partner")
        c1=${counts[$p1]:-0}
        c2=${counts[$p2]:-0}
        echo "Pair: $p1 ↔ $p2 | pkts: $c1 vs $c2 | diff=$((c1-c2))"
    fi
done
