#! /bin/bash
set -euo pipefail

show_help() {
  cat <<'EOF'
Usage: utils/process_result_pcaps.sh [options]

Process pcaps in ./pcaps matching pe_l?-eth?_out.pcap and output a combined CSV.

Options:
  -i, --input-dir PATH   Input directory containing PCAP files (default: ./pcaps)
      --input-dir=PATH   Same as above
  -o, --output-csv PATH   Output CSV file (default: ./pcaps/combined.csv)
      --output-csv=PATH   Same as above
  -h, --help              Show this help and exit
EOF
}

# Default parameter
output_csv="./pcaps/combined.csv"
input_dir="./pcaps"

# Argument parsing
while (($#)); do
  case "$1" in
    -i|--input-dir)
      [[ ${2:-} ]] || { echo "Error: $1 requires a non-empty value" >&2; exit 1; }
      input_dir=$2; shift 2 ;;
    --input-dir=*)
      input_dir=${1#*=}
      [[ $input_dir ]] || { echo "Error: --input-dir requires a non-empty value" >&2; exit 1; }
      shift ;;
    -o|--output-csv)
      [[ ${2:-} ]] || { echo "Error: $1 requires a non-empty value" >&2; exit 1; }
      output_csv=$2; shift 2 ;;
    --output-csv=*)
      output_csv=${1#*=}
      [[ $output_csv ]] || { echo "Error: --output-csv requires a non-empty value" >&2; exit 1; }
      shift ;;
    -h|--help)
      show_help; exit 0 ;;
    --)
      shift; break ;;
    *)
      echo "Error: Unknown option: $1" >&2
      show_help; exit 1 ;;
  esac
done

[[ -d $input_dir ]] || { echo "Error: input dir '$input_dir' not found" >&2; exit 1; }

mkdir -p "$(dirname "$output_csv")"
: > "$output_csv"  # truncate if exists

process_pcap() {
  local input_file=$1
  local output_file=$2
  local header_needed=0
  if [ ! -s "$output_file" ]; then
    header_needed=1
  fi

  # Added filter: only packets where dune.class != 0
  tshark -r "$input_file" -T fields -E header=y -E separator=, -E quote=d \
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

for file in $input_dir/*.pcap; do
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

# Deduplicate rows (keep header + first occurrence of each data row)
# if [[ -s "$output_csv" ]]; then
#   awk 'NR==1{print;next}!seen[$0]++' "$output_csv" > "${output_csv}.tmp"
#   mv "${output_csv}.tmp" "$output_csv"
# fi

echo "Wrote $output_csv"
