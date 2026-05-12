# SQUIRM v2 - Clean Recon

Streamlined bash recon pipeline. Subdomains → alive → endpoints → JSON → entropy.

## 🚀 Quick Start

### Install Dependencies

**Ubuntu/Debian (apt):**
```bash
sudo apt update && sudo apt install -y curl jq python3 python3-pip golang-go && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && go install -v github.com/projectdiscovery/katana/cmd/katana@latest && pip3 install httpie
```

**Arch Linux (pacman):**
```bash
sudo pacman -Syu && sudo pacman -S curl jq python3 go httpie && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && go install -v github.com/projectdiscovery/katana/cmd/katana@latest && pip install httpie
```

Then add Go binaries to PATH:
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### Quick Setup

```bash
git clone https://github.com/whathehack81/squirm
cd squirm
chmod +x squirm.sh brain.sh
./squirm.sh -t example.com
```

## 📋 Usage

```bash
./squirm.sh -t target.com [OPTIONS]

Options:
  --target, -t DOMAIN        Target domain to scan
  --scope FILE               Scope file (one domain per line)
  --proxy URL                HTTP proxy (e.g., http://127.0.0.1:8080)
  --out-dir DIR              Output directory (default: intel/)
  --fast                     Skip endpoint collection
  --entropy                  Enable entropy scanning for secrets
  --help, -h                 Show help
```

### Examples

```bash
# Single target, full scan
./squirm.sh -t example.com

# Fast mode (no endpoints)
./squirm.sh -t example.com --fast

# With entropy scanning for secrets
./squirm.sh -t example.com --entropy

# Through proxy
./squirm.sh -t example.com --proxy http://127.0.0.1:8080

# Batch scan from scope file
./squirm.sh --scope targets.txt
```

## 📊 Output Structure

```
intel/target.com/
├── raw/
│   ├── subdomains.txt           # All discovered subdomains
│   ├── alive.txt                # Live/responsive hosts
│   ├── endpoints.txt            # Raw endpoints from GAU
│   └── cleaned-endpoints.txt    # Filtered & denoised endpoints
├── classified/
│   ├── auth.txt                 # Authentication endpoints
│   ├── platform.txt             # Internal/platform endpoints
│   ├── features.txt             # Feature-specific endpoints
│   └── frontend.txt             # JavaScript/frontend assets
├── flags/
│   ├── entropy-input.txt        # URLs for entropy scanning
│   └── entropy-candidates.txt   # Detected secrets/tokens
└── report.json                  # Structured intelligence report
```

## 🧠 SQUIRM Brain v2 - Intelligent Classification

The Brain system automatically scores and prioritizes endpoints:

```bash
./brain.sh target.com
```

**Scoring System:**
- **90+**: CRITICAL (SSRF, file interaction, config exposure)
- **80-89**: HIGH (financial, admin, auth, IDOR)
- **60-79**: MEDIUM (debug, staging, non-prod)
- **25-59**: LOW (generic endpoints)
- **5-24**: STATIC (assets, images, styles)
- **0-5**: NOISE (marketing, blogs, irrelevant content)

**Output:**
```
intel/target.com/brain-output.txt   # Full scored results
intel/target.com/high-value.txt     # Only 80+ priority targets
```

## 🔧 Dependencies

| Tool | Purpose | Source |
|------|---------|--------|
| `subfinder` | Subdomain enumeration | ProjectDiscovery |
| `httpx` | HTTP probing | ProjectDiscovery |
| `katana` | Endpoint crawling | ProjectDiscovery |
| `gau` | URL archiving | Tomnomnom |
| `jq` | JSON processing | stedolan |
| `curl` | HTTP requests | curl project |
| `httpie` | HTTP CLI | httpie.io |
| `python3` | Python runtime | Python |
| `pip` | Package manager | Python |

## 🎯 Workflow

1. **Enumeration**: subfinder discovers subdomains
2. **Probing**: httpx checks which are alive
3. **Collection**: gau + katana gather historical endpoints
4. **Cleaning**: Noise filtering & deduplication
5. **Classification**: Brain categorizes by risk level
6. **Analysis**: Entropy scanning detects potential secrets
7. **Reporting**: JSON output for automation/integration

## ⚡ Performance Tips

- Use `--fast` mode for quick reconnaissance
- Run entropy scanning separately for large datasets
- Batch process with `--scope` for multiple targets
- Use proxy to distribute load and avoid rate limiting

## 🐍 Python Version (In Development)

A Python rewrite is in progress with:
- Contract-based module architecture
- Enhanced classification algorithms
- Better performance & concurrency
- Type-hinted codebase

## 🤝 Contributing

Found a bug? Have suggestions? Open an issue or submit a PR!

**Current Focus:**
- Python module refactoring
- Performance optimization
- Classification algorithm improvements

## 📄 License

See LICENSE file for details.

---

**Last Updated:** 2026-05-12 | **Status:** Active Development
