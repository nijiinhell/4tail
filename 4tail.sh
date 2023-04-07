#!/bin/bash

# Prompt user to input new names for subdomains file and alive subdomains file
echo "Enter new name for subdomains file (default: subdomains.txt):"
read subdomains_file
subdomains_file=${subdomains_file:-"subdomains.txt"}

echo "Enter new name for alive subdomains file (default: alivesubdomains.txt):"
read alive_subdomains_file
alive_subdomains_file=${alive_subdomains_file:-"alivesubdomains.txt"}

domain=$1

# Check for required argument
if [ -z "$domain" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

# Generate the name for the alive subdomains file
filename_without_ext="${subdomains_file%.*}"
alive_subdomains_file="alive_$filename_without_ext.txt"

# Generate the name for the fuzzing results file
fuzzing_results_file="fuzzying_$filename_without_ext.txt"

# Check for subdomains and save to a file
subfinder -d "$domain" -o "$subdomains_file"

# Check aliveness of subdomains and save alive ones to another file
cat "$subdomains_file" | httpx | anew "$alive_subdomains_file"

echo "Alive subdomains saved to $alive_subdomains_file"

# Perform fuzzing on alive subdomains and save results to a file
echo "Performing fuzzing on alive subdomains..."
while read -r url; do
  echo "Fuzzing: $url"
  echo "Results for $url:" >> "$fuzzing_results_file"
  ffuf -u "$url/FUZZ" -w /root/Desktop/tool/fuzz4bounty/fuzz4bounty/fuzz4bounty.txt -mc 200,301,401 >> "$fuzzing_results_file"
  tail -n +1 "$fuzzing_results_file"
done < "$alive_subdomains_file"

echo "Fuzzing results saved to $fuzzing_results_file"

# Perform vulnerability scanning on alive subdomains
echo "Performing vulnerability scanning on alive subdomains..."
nuclei -tags cves,osint,tech -l "$alive_subdomains_file" | anew nuclei_results.txt

echo "Vulnerability scanning results saved to nuclei_results.txt"

