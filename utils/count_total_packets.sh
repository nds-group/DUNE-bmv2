#!/bin/bash

# Check usage
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <pcap-folder>"
    exit 1
fi

folder="$1"

if [[ ! -d "$folder" ]]; then
    echo "Error: $folder is not a directory"
    exit 1
fi

total=0

shopt -s nullglob  # avoid literal *.pcap if no match
for f in "$folder"/*.pcap "$folder"/*.pcapng; do
    if [[ -f "$f" ]]; then
        count=$(tshark -r "$f" | wc -l)
        echo "$(basename "$f"): $count packets"
        total=$((total + count))
    fi
done

echo "-------------------------"
echo "Total packets across traces in $folder: $total"

