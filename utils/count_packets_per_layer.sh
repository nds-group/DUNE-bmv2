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
for f in "$folder"/p[0123]_l?-eth?_in.pcap "$folder"/*.pcapng; do
    [ -s "$f" ] || continue   # skip zero-size files
    if [[ -f "$f" ]]; then
	count=$(capinfos -T -c -r "$f" | awk -F'\t' '{print $2}')
        #echo "$(basename "$f"): $count packets"
        total=$((total + count))
    fi
done

echo "-------------------------"
echo "Total packets across leaf layer (in): $total"

total=0
for f in "$folder"/p[0123]_l?-eth?_out.pcap "$folder"/*.pcapng; do
    [ -s "$f" ] || continue   # skip zero-size files
    if [[ -f "$f" ]]; then
	count=$(capinfos -T -c -r "$f" | awk -F'\t' '{print $2}')
        #echo "$(basename "$f"): $count packets"
        total=$((total + count))
    fi
done

echo "Total packets across leaf layer(out): $total"

total=0
for f in "$folder"/p[0123]_s?-eth?_in.pcap "$folder"/*.pcapng; do
    [ -s "$f" ] || continue   # skip zero-size files
    if [[ -f "$f" ]]; then
	count=$(capinfos -T -c -r "$f" | awk -F'\t' '{print $2}')
        #echo "$(basename "$f"): $count packets"
        total=$((total + count))
    fi
done

echo "-------------------------"
echo "Total packets across spine layer(in): $total"

total=0
for f in "$folder"/p[0123]_s?-eth?_out.pcap "$folder"/*.pcapng; do
    [ -s "$f" ] || continue   # skip zero-size files
    if [[ -f "$f" ]]; then
	count=$(capinfos -T -c -r "$f" | awk -F'\t' '{print $2}')
        #echo "$(basename "$f"): $count packets"
        total=$((total + count))
    fi
done

echo "Total packets across spine layer(out): $total"


total=0
for f in "$folder"/ss_?_?-eth?_in.pcap "$folder"/*.pcapng; do
    [ -s "$f" ] || continue   # skip zero-size files
    if [[ -f "$f" ]]; then
	count=$(capinfos -T -c -r "$f" | awk -F'\t' '{print $2}')
        #echo "$(basename "$f"): $count packets"
        total=$((total + count))
    fi
done

echo "-------------------------"
echo "Total packets across super spine layer(in): $total"

total=0
for f in "$folder"/ss_?_?-eth?_out.pcap "$folder"/*.pcapng; do
    [ -s "$f" ] || continue   # skip zero-size files
    if [[ -f "$f" ]]; then
	count=$(capinfos -T -c -r "$f" | awk -F'\t' '{print $2}')
        #echo "$(basename "$f"): $count packets"
        total=$((total + count))
    fi
done

echo "Total packets across super spine layer(out): $total"

total=0
for f in "$folder"/pe_s?-eth?_in.pcap "$folder"/*.pcapng; do
    [ -s "$f" ] || continue   # skip zero-size files
    if [[ -f "$f" ]]; then
	count=$(capinfos -T -c -r "$f" | awk -F'\t' '{print $2}')
        #echo "$(basename "$f"): $count packets"
        total=$((total + count))
    fi
done

echo "-------------------------"
echo "Total packets across egress spine layer(in): $total"

total=0
for f in "$folder"/pe_s?-eth?_out.pcap "$folder"/*.pcapng; do
    [ -s "$f" ] || continue   # skip zero-size files
    if [[ -f "$f" ]]; then
	count=$(capinfos -T -c -r "$f" | awk -F'\t' '{print $2}')
        #echo "$(basename "$f"): $count packets"
        total=$((total + count))
    fi
done

echo "Total packets across egress spine layer(out): $total"

total=0
for f in "$folder"/pe_l?-eth?_in.pcap "$folder"/*.pcapng; do
    [ -s "$f" ] || continue   # skip zero-size files
    if [[ -f "$f" ]]; then
	count=$(capinfos -T -c -r "$f" | awk -F'\t' '{print $2}')
        #echo "$(basename "$f"): $count packets"
        total=$((total + count))
    fi
done

echo "-------------------------"
echo "Total packets across egress leaf layer (in): $total"

total=0
for f in "$folder"/pe_l?-eth?_out.pcap "$folder"/*.pcapng; do
    [ -s "$f" ] || continue   # skip zero-size files
    if [[ -f "$f" ]]; then
	count=$(capinfos -T -c -r "$f" | awk -F'\t' '{print $2}')
        #echo "$(basename "$f"): $count packets"
        total=$((total + count))
    fi
done

echo "Total packets across egress leaf layer(out): $total"
