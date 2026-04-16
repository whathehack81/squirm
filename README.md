SQUIRM v2 - Clean Recon

Streamlined bash recon pipeline. Subdomains → alive → endpoints → JSON → entropy.
Install

git clone https://github.com/whathehack81/squirm
cd squirm
chmod +x squirm.sh
./squirm.sh -t example.com
Usage

./squirm.sh -t target.com --proxy http://127.0.0.1:8080 --entropy

See squirm.sh --help.
Outputs

intel/target.com/subs.txt
intel/target.com/alive.txt
intel/target.com/endpoints.txt
intel/target.com/report.json
intel/target.com/flags/entropy-candidates.txt

Deps: subfinder httpx-toolkit gau jq
