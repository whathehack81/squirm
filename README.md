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

## 🚀 SQUIRM v2.1 - Brain Pipeline NEW

**`./squirm.sh target.com` → auto-runs `brain.sh` → extracts `high-value.txt`**

subfinder → httpx → gau → brain classification → high-value.txt (scores 80+)

text

**Outputs:**

intel/target.com/
├── subs.txt # 127 subdomains
├── alive.txt # 23 live hosts
├── endpoints.txt # JS/API endpoints
├── report.json # structured intel
├── brain-output.txt # full classification
└── high-value.txt # 🔥 PRIORITY TARGETS ONLY

text

**Usage:**
\`\`\`bash
./squirm.sh -t target.com        # full pipeline
./squirm.sh -t target.com --fast   # skip endpoints
\`\`\`

**Deps:** \`subfinder httpx-toolkit gau jq brain.sh\`
