#!/bin/bash

# Check usage
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <log-folder>"
    exit 1
fi

folder="$1"

if [[ ! -d "$folder" ]]; then
    echo "Error: $folder is not a directory"
    exit 1
fi

total=0

for f in "$folder"/p[01234]_l?.log; do
    if [[ -f "$f" ]]; then
        count=$(grep "Processing packet" "$f" | wc -l)
        echo "$(basename "$f"): $count packets"
        total=$((total + count))
    fi
done

echo "-------------------------"
echo "Total packets across logs in $folder: $total"

