#! /bin/bash
set -euo pipefail

# Output CSV (single combined file)
output_csv=./pcaps/combined.csv
: > "$output_csv"  # truncate if exists

process_pcap() {
  local input_file=$1
  local output_file=$2
  local header_needed=0
  if [ ! -s "$output_file" ]; then
    header_needed=1
  fi

  # Added filter: only packets where dune.class != 0
  tshark -r "$input_file" -Y "dune.class != 0" -T fields -E header=y -E separator=, -E quote=d \
    -e ip.src -e ip.dst -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e ip.proto \
    -e dune.orig_ethertype -e dune.class_type -e dune.class -e dune.collision -e dune.model_id -e dune.mpls_label \
  | awk -v need_header="$header_needed" -F, '
    NR==1{
      if(need_header)
        print "src_ip,dst_ip,src_port,dst_port,transport_proto,orig_ethertype,class_type,class,collision,model_id,mpls_label";
      next
    }
    {
      src=$1; dst=$2;
      sport=$3; if(sport=="") sport=$4;
      dport=$5; if(dport=="") dport=$6;
      proto=$7;
      printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", src,dst,sport,dport,proto,$8,$9,$10,$11,$12,$13
    }' >> "$output_file"
}

for file in ./pcaps/*.pcap; do
       # Only process regular, non-empty files
	if [[ -f "$file" && -s "$file" ]]; then
        # Extract just the filename (no path)
		fname=$(basename "$file")
		if [[ "$fname" == pe_l?-eth?_out.pcap ]]; then
			echo "Processing $file"
			process_pcap "$file" "$output_csv"
		fi
	fi
done
#
# Deduplicate rows (keep header + first occurrence of each data row)
# if [[ -s "$output_csv" ]]; then
#   awk 'NR==1{print;next}!seen[$0]++' "$output_csv" > "${output_csv}.tmp"
#   mv "${output_csv}.tmp" "$output_csv"
# fi

echo "Wrote $output_csv"
