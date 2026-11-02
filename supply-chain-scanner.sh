#!/usr/bin/env bash
# scan-supply-chain.sh — Supply Chain Malware Scanner
# Threats: PolinRider, InvisibleFerret, Megalodon, compromised npm packages
# Read-only: does NOT modify any files or system state
# Safe: never prints credential or token values
#
# Usage: ./scan-supply-chain.sh [--scan-dirs "/path/a /path/b"]
# --scan-dirs  Override default source code directories to scan

set -uo pipefail

VERSION="1.2.0"

# ─── Configuration ────────────────────────────────────────────────────────────

DEFAULT_SCAN_DIRS="$HOME"
SCAN_DIRS="${SCAN_DIRS:-$DEFAULT_SCAN_DIRS}"
MAX_DEPTH=6

EXCLUDE_DIRS="node_modules .next dist .git build .turbo .expo .cache Library .Trash .local .nvm .cargo .rustup .docker .colima .orbstack .lima .cache go .gradle .m2 .npm .pnpm-store .yarn .bun Pictures Music Movies Applications"

# Known C2 indicators
C2_IPS="166\.88\.54\.158|198\.105\.127\.210|23\.27\.202\.27|44\.206\.172\.239|195\.201\.194\.107|107\.189\.20\.115|216\.126\.237\.71|216\.126\.224\.220|95\.216\.26\.109|165\.140\.86\.52|66\.235\.175\.48|38\.92\.47\.157|45\.140\.184\.41|136\.0\.9\.8|154\.91\.0\.196|23\.27\.20\.143|85\.239\.62\.36|83\.168\.68\.219|166\.88\.4\.2|23\.27\.120\.142"

C2_DOMAINS="trongrid|aptoslabs|bsc-dataseed|bsc-rpc\.publicnode|api\.telegram\.org|coingecko-liard\.vercel|jsonkeeper\.com|api-sub\.jrodacooker|api\.npoint\.io|jsonspack|nexafilm|deoft|pricesheet|mywalletsss|regioncheck\.xyz"

C2_VERCEL="default-configuration\.vercel|vscode-settings-bootstrap\.vercel|vscode-load-config\.vercel|260120\.vercel|coingecko-liard\.vercel|cloudflareinsights\.vercel|axioshealthcheck\.vercel|logkit-tau\.vercel|wallet-management-tg-bot\.vercel|polymarkettrading\.vercel|npmjs-doc-builder\.vercel|chalk-logger\.vercel|cloudflare-protection\.vercel|cloudflarefirewall\.vercel|cloudflareguard\.vercel|cloudflaresecurity\.vercel|cloudflareshield\.vercel|locate-my-ip\.vercel|vscode-config-settings\.vercel|vscode-extension-260120\.vercel|vscode-settings-config\.vercel|vscode-extensions-bootstrap\.vercel|davhub88\.vercel|codeviewer-three\.vercel|coreviewer\.vercel|vscode-helper171\.vercel|task-hrec\.vercel|vscode-bootstrapper\.vercel|vscode-production-setting\.vercel|vscode-toolkit-settings\.vercel|tailwind-version-4\.vercel|vscode-ext-git\.vercel|thopywork\.vercel|isvalid-regions\.vercel|ext-checkedin\.vercel|data-kappa\.vercel|apiscriptv3\.vercel|server-check-genimi\.vercel|server-genimi-check\.vercel"

# Malicious npm packages (PolinRider + indece + Panther DPRK campaign)
MALICIOUS_PKGS="tailwindcss-style-animate|tailwind-mainanimation|tailwind-tionbased|tailwindcss-typography-style|tailwindcss-style-modify|tailwindcss-animate-style|crypto-keccak-js|simple-auth-basic|swplayer-react-sl|tailwind-typography-cssstyle|tailwindcss-style-typography|tailwind-stylecss-typography|tailwind-typ|tailwindthml-flips|tailwind-lines-clamp|chai-use-chains|trgrip|js-logger-pack|tailwind-animationbasic|tailwind-configuration|tailwind-scroller|tailwind-text-fill|tailwindcss-fonttype-inter|tailwindcss-typeface-inter|chai-as-adapter|chai-as-chain-v2|chai-as-char|chai-as-elevated|chai-as-encrypted|chai-as-evm|chai-as-hooked|chai-as-ide|chai-as-init|chai-as-inserted|chai-as-mobj|chai-as-nobj|chai-as-optimized|chai-as-refined|chai-as-type|chai-beta|chai-chain-coremesh|chai-extensions-extras|chalk-ts-logger|cli-pretty-logger|color-cli-log|dev-log-core|jonas-prettier-logger|log-upgrade|pino-pretty-logs|prettier-logger|terminal-structured-logger|express-flowlimit|winston-prism|vite-enhancer-config|request-js-validator|mongoose-lean-hooks|polymarket-onchain-sdk|mexc-utils-helper|sol-sdk|ts-relayer-client|relion-chain|metrify-chain|trackora-chain|bundrix|argonflux|byteboxlab|byteutilsbox|cookie-parseflow|coremesh|express-auth-basic|express-lib-validator|express-session-validator|json-spectaculation|jsontoken-extend|levex-press|peptide-score|peptideenv|rollup-plugin-polyfill-route|vime-azl|wime-zle|atddevs|farm-orchestrator|farm-runner|df-vision|appclaw"

# Known malicious npm accounts (indece + Panther reports)
MALICIOUS_NPM_ACCOUNTS="msafe-ci|cubistengineer|ficara9076|calebguo|wakiye8356|codeforge1144|lancer110|lancer117|tailwind11995|mwai2006|joshsingh|jpeek868|jsonspack|corvettdan1963|chainlence|vynlence|koldavich|ronaldobon"

# Known malicious SSH keys (js-logger-pack)
MALICIOUS_SSH_KEY="bink@DESKTOP-N8JGD6T"

# Known malicious LaunchAgents (trgrip)
MALICIOUS_LAUNCHAGENTS="com.bablu.helper.plist"

# Known safe postinstall commands (prefix match)
SAFE_POSTINSTALL="prisma generate|patch-package|husky|ngcc|electron-rebuild|node-gyp|esbuild|tsc |tsx |ts-node|npx prisma|playwright install|puppeteer install|opencollective|is-ci|npm run build|pnpm run build|yarn build|expo-configure-project|pod-install"

# ─── Output helpers ───────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

TOTAL_CHECKS=28
if [[ "$(uname)" == "Darwin" ]]; then TOTAL_CHECKS=30; fi
CURRENT=0
declare -a CHECK_NAMES=()
declare -a CHECK_RESULTS=()
declare -a CHECK_DETAILS=()
FINDINGS=0

header() {
  CURRENT=$((CURRENT + 1))
  printf "\n${CYAN}[%2d/%d]${NC} ${BOLD}%s${NC}\n" "$CURRENT" "$TOTAL_CHECKS" "$1"
}

pass()   { printf "       ${GREEN}✅ %s${NC}\n" "$1"; }
warn()   { printf "       ${YELLOW}⚠️  %s${NC}\n" "$1"; FINDINGS=$((FINDINGS + 1)); }
fail()   { printf "       ${RED}🔴 %s${NC}\n" "$1"; FINDINGS=$((FINDINGS + 1)); }
detail() { printf "       ${DIM}   %s${NC}\n" "$1"; }

record() {
  CHECK_NAMES+=("$1")
  CHECK_RESULTS+=("$2")
}

# ─── Resolve scan directories ────────────────────────────────────────────────

RESOLVED_DIRS=()

resolve_dirs() {
  for dir in $SCAN_DIRS; do
    if [[ -d "$dir" ]]; then
      RESOLVED_DIRS+=("$dir")
    fi
  done
  if [[ ${#RESOLVED_DIRS[@]} -eq 0 ]]; then
    printf "${YELLOW}Warning: no scan directories found. Checked: %s${NC}\n" "$SCAN_DIRS"
    printf "Override with: SCAN_DIRS=\"/your/code\" ./scan-supply-chain.sh\n"
  fi
}

# Build find exclude arguments: -path '*/node_modules' -prune -o ...
build_find_excludes() {
  local excludes=""
  for d in $EXCLUDE_DIRS; do
    excludes="$excludes -path '*/$d' -prune -o"
  done
  echo "$excludes"
}

# Build grep exclude-dir arguments
build_grep_excludes() {
  local excludes=""
  for d in $EXCLUDE_DIRS; do
    excludes="$excludes --exclude-dir=$d"
  done
  echo "$excludes"
}

GREP_EXCLUDES=$(build_grep_excludes)

# ─── Check functions ─────────────────────────────────────────────────────────

# 1. Lock file — direct evidence of payload execution
check_lock_file() {
  header "Lock file (payload execution marker)"
  local lockfile="/tmp/tmp7A863DD1.tmp"
  if [[ -f "$lockfile" ]]; then
    fail "LOCK FILE EXISTS at $lockfile — payload executed on this machine"
    detail "$(ls -la "$lockfile")"
    record "Lock file" "🔴"
  else
    pass "Not found"
    record "Lock file" "✅"
  fi
}

# 2. Credential dumps in ~/.npm staging directory
check_credential_dumps() {
  header "Credential dumps (~/.npm staging)"
  local found=0
  local files
  files=$(find "$HOME/.npm" \( \
    -name "_credentials.json" -o \
    -name "_sysenv.json" -o \
    -name "_sysenv.env" -o \
    -name "_info.json" -o \
    -name "*.zip" \
  \) 2>/dev/null || true)

  if [[ -n "$files" ]]; then
    found=$(echo "$files" | wc -l | tr -d ' ')
    fail "CREDENTIAL DUMPS FOUND — $found file(s) in ~/.npm"
    echo "$files" | while IFS= read -r f; do
      detail "$(ls -la "$f" 2>/dev/null)"
    done
    detail "DO NOT delete these — they are forensic evidence"
    record "Credential dumps" "🔴"
  else
    pass "No suspicious files"
    record "Credential dumps" "✅"
  fi
}

# 3. Active network connections to known C2
check_network_c2() {
  header "Active C2 network connections"
  local hits
  hits=$(netstat -an 2>/dev/null | grep -iE "$C2_IPS" || true)
  if [[ -n "$hits" ]]; then
    fail "ACTIVE CONNECTION TO C2 SERVER"
    echo "$hits" | while IFS= read -r line; do detail "$line"; done
    record "C2 connections" "🔴"
  else
    pass "No active connections to known C2 IPs"
    record "C2 connections" "✅"
  fi
}

# 4. InvisibleFerret active processes
check_invisibleferret() {
  header "InvisibleFerret RAT processes"
  local hits
  hits=$(ps aux 2>/dev/null | grep -iE "__DAEMONIZED|cat\.py" | grep -v grep || true)
  if [[ -n "$hits" ]]; then
    fail "INVISIBLEFERRET PROCESS DETECTED"
    echo "$hits" | while IFS= read -r line; do detail "$line"; done
    record "InvisibleFerret" "🔴"
  else
    pass "No InvisibleFerret processes found"
    record "InvisibleFerret" "✅"
  fi
}

# 5. Known malware signatures in JS files
check_malware_signatures() {
  header "Known malware signatures in source files"
  [[ ${#RESOLVED_DIRS[@]} -eq 0 ]] && { pass "No directories to scan"; record "Malware signatures" "⏭️"; return; }

  local hits
  hits=$(grep -rl $GREP_EXCLUDES \
    --include='*.js' --include='*.mjs' --include='*.cjs' --include='*.ts' \
    -E "rmcej%otb%|Cot%3t=shtP|_\\\$_[a-f0-9]{4}|_0x[a-f0-9]{4}|global\['\w{1,3}'\]\s*=|globalThis\['\w{1,3}'\]\s*=" \
    "${RESOLVED_DIRS[@]}" 2>/dev/null || true)

  if [[ -n "$hits" ]]; then
    local count
    count=$(echo "$hits" | wc -l | tr -d ' ')
    fail "MALWARE SIGNATURES FOUND in $count file(s)"
    echo "$hits" | head -20 | while IFS= read -r f; do detail "$f"; done
    [[ $count -gt 20 ]] && detail "... and $((count - 20)) more"
    record "Malware signatures" "🔴"
  else
    pass "No known signatures found"
    record "Malware signatures" "✅"
  fi
}

# 6. Suspiciously long lines in config files (payload hides after ~1300 spaces)
check_long_config_lines() {
  header "Suspiciously long config lines (>200 chars)"
  [[ ${#RESOLVED_DIRS[@]} -eq 0 ]] && { pass "No directories to scan"; record "Long config lines" "⏭️"; return; }

  local config_names="-name 'postcss.config.*' -o -name 'next.config.*' -o -name 'tailwind.config.*' \
    -o -name 'eslint.config.*' -o -name 'babel.config.*' -o -name 'jest.config.*' \
    -o -name 'vite.config.*' -o -name 'tsup.config.*' -o -name 'astro.config.*' \
    -o -name 'webpack.config.*' -o -name 'vue.config.*' -o -name 'App.js'"

  local found=0
  local output=""

  for dir in "${RESOLVED_DIRS[@]}"; do
    while IFS= read -r file; do
      [[ -z "$file" ]] && continue
      local longest
      longest=$(awk '{ print length }' "$file" 2>/dev/null | sort -rn | head -1)
      if [[ -n "$longest" ]] && [[ "$longest" -gt 200 ]] 2>/dev/null; then
        output+="⚠️  SUSPICIOUS ($longest chars): $file"$'\n'
        found=$((found + 1))
      fi
    done < <(find "$dir" -maxdepth "$MAX_DEPTH" \
      -path '*/node_modules' -prune -o \
      -path '*/.next' -prune -o \
      -path '*/dist' -prune -o \
      -path '*/.git' -prune -o \
      \( -name 'postcss.config.*' -o -name 'next.config.*' -o -name 'tailwind.config.*' \
         -o -name 'eslint.config.*' -o -name 'babel.config.*' -o -name 'jest.config.*' \
         -o -name 'vite.config.*' -o -name 'tsup.config.*' -o -name 'astro.config.*' \
         -o -name 'webpack.config.*' -o -name 'vue.config.*' -o -name 'App.js' \) \
      -print 2>/dev/null)
  done

  if [[ $found -gt 0 ]]; then
    warn "FOUND $found config file(s) with suspiciously long lines"
    echo "$output" | while IFS= read -r line; do [[ -n "$line" ]] && detail "$line"; done
    detail "Inspect these files — the payload hides after ~1300 trailing spaces"
    record "Long config lines" "⚠️"
  else
    pass "All config files have normal line lengths"
    record "Long config lines" "✅"
  fi
}

# 7. Fake font files (.woff2 containing JS)
check_fake_fonts() {
  header "Fake font payloads (.woff2 with JS)"
  [[ ${#RESOLVED_DIRS[@]} -eq 0 ]] && { pass "No directories to scan"; record "Fake fonts" "⏭️"; return; }

  local found=0
  for dir in "${RESOLVED_DIRS[@]}"; do
    while IFS= read -r file; do
      [[ -z "$file" ]] && continue
      if head -c 100 "$file" 2>/dev/null | grep -qE "global|function|require|module\.exports"; then
        warn "JS payload in font: $file"
        found=$((found + 1))
      fi
    done < <(find "$dir" -maxdepth "$MAX_DEPTH" \
      -path '*/node_modules' -prune -o \
      -path '*/.next' -prune -o \
      -name '*.woff2' -print 2>/dev/null)
  done

  if [[ $found -gt 0 ]]; then
    record "Fake fonts" "⚠️"
  else
    pass "No fake font payloads found"
    record "Fake fonts" "✅"
  fi
}

# 8. Malicious npm packages in package.json
check_malicious_packages() {
  header "Malicious npm packages in package.json"
  [[ ${#RESOLVED_DIRS[@]} -eq 0 ]] && { pass "No directories to scan"; record "Malicious packages" "⏭️"; return; }

  local hits
  hits=$(grep -rl $GREP_EXCLUDES \
    --include='package.json' \
    -E "$MALICIOUS_PKGS" \
    "${RESOLVED_DIRS[@]}" 2>/dev/null || true)

  if [[ -n "$hits" ]]; then
    local count
    count=$(echo "$hits" | wc -l | tr -d ' ')
    fail "MALICIOUS PACKAGES in $count package.json file(s)"
    echo "$hits" | while IFS= read -r f; do detail "$f"; done
    record "Malicious packages" "🔴"
  else
    pass "No known malicious packages found"
    record "Malicious packages" "✅"
  fi
}

# 9. VS Code tasks.json with C2 domains
check_vscode_tasks() {
  header "VS Code tasks.json with C2 domains"
  [[ ${#RESOLVED_DIRS[@]} -eq 0 ]] && { pass "No directories to scan"; record "tasks.json C2" "⏭️"; return; }

  local hits
  hits=$(grep -rl $GREP_EXCLUDES \
    --include='tasks.json' \
    -E "$C2_VERCEL|e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9" \
    "${RESOLVED_DIRS[@]}" 2>/dev/null || true)

  if [[ -n "$hits" ]]; then
    fail "MALICIOUS tasks.json FOUND"
    echo "$hits" | while IFS= read -r f; do detail "$f"; done
    record "tasks.json C2" "🔴"
  else
    pass "No malicious tasks.json files found"
    record "tasks.json C2" "✅"
  fi
}

# 10. Solana/blockchain C2 patterns in source code
check_solana_c2() {
  header "Solana/blockchain C2 patterns in source"
  [[ ${#RESOLVED_DIRS[@]} -eq 0 ]] && { pass "No directories to scan"; record "Blockchain C2" "⏭️"; return; }

  local hits
  hits=$(grep -rl $GREP_EXCLUDES \
    --include='*.js' --include='*.mjs' --include='*.cjs' --include='*.ts' \
    -E "@solana/web3|trongrid|wallet.*memo" \
    "${RESOLVED_DIRS[@]}" 2>/dev/null || true)

  if [[ -n "$hits" ]]; then
    local count
    count=$(echo "$hits" | wc -l | tr -d ' ')
    warn "BLOCKCHAIN REFERENCES in $count file(s) — verify if legitimate"
    echo "$hits" | head -10 | while IFS= read -r f; do detail "$f"; done
    detail "May be legitimate if this project uses Solana/Tron — verify manually"
    record "Blockchain C2" "⚠️"
  else
    pass "No blockchain C2 patterns found"
    record "Blockchain C2" "✅"
  fi
}

# 11. Compromised axios versions (1.14.1, 0.30.4)
check_axios_compromised() {
  header "Compromised axios versions"
  [[ ${#RESOLVED_DIRS[@]} -eq 0 ]] && { pass "No directories to scan"; record "Axios versions" "⏭️"; return; }

  local hits
  hits=$(grep -rl $GREP_EXCLUDES \
    --include='package.json' --include='pnpm-lock.yaml' \
    --include='package-lock.json' --include='yarn.lock' \
    -E '"axios":\s*"(1\.14\.1|0\.30\.4)"|axios@(1\.14\.1|0\.30\.4)' \
    "${RESOLVED_DIRS[@]}" 2>/dev/null || true)

  if [[ -n "$hits" ]]; then
    fail "COMPROMISED AXIOS VERSION found"
    echo "$hits" | while IFS= read -r f; do detail "$f"; done
    detail "axios 1.14.1 and 0.30.4 were published by a compromised maintainer"
    record "Axios versions" "🔴"
  else
    pass "No compromised axios versions found"
    record "Axios versions" "✅"
  fi
}

# 12. Nx Console CVE-2026-48027
check_nx_console() {
  header "Nx Console extension (CVE-2026-48027)"
  local exts=""
  exts=$(code --list-extensions --show-versions 2>/dev/null || \
         cursor --list-extensions --show-versions 2>/dev/null || true)

  if echo "$exts" | grep -iqE "nrwl\.angular-console|nx-console"; then
    local version
    version=$(echo "$exts" | grep -iE "nrwl|nx-console" | head -1)
    if echo "$version" | grep -q "18\.95\.0"; then
      fail "COMPROMISED Nx Console v18.95.0 installed — update to 18.100.0+"
      detail "$version"
      record "Nx Console" "🔴"
    else
      pass "Nx Console installed but version is safe: $version"
      record "Nx Console" "✅"
    fi
  else
    pass "Nx Console not installed"
    record "Nx Console" "✅"
  fi
}

# 13. Suspicious postinstall/preinstall scripts
check_postinstall_scripts() {
  header "Suspicious postinstall/preinstall scripts"
  [[ ${#RESOLVED_DIRS[@]} -eq 0 ]] && { pass "No directories to scan"; record "postinstall" "⏭️"; return; }

  local found=0
  for dir in "${RESOLVED_DIRS[@]}"; do
    while IFS= read -r pkg; do
      [[ -z "$pkg" ]] && continue
      local scripts
      scripts=$(python3 -c "
import json, sys
try:
    d = json.load(open('$pkg'))
    s = d.get('scripts', {})
    for k in ('postinstall', 'preinstall'):
        if k in s:
            print(f'{k}: {s[k]}')
except: pass
" 2>/dev/null || true)

      if [[ -n "$scripts" ]]; then
        while IFS= read -r script_line; do
          local cmd="${script_line#*: }"
          local is_safe=false
          IFS='|' read -ra safe_patterns <<< "$SAFE_POSTINSTALL"
          for pattern in "${safe_patterns[@]}"; do
            if [[ "$cmd" == *"$pattern"* ]]; then
              is_safe=true
              break
            fi
          done
          if ! $is_safe; then
            warn "REVIEW: $pkg"
            detail "$script_line"
            found=$((found + 1))
          fi
        done <<< "$scripts"
      fi
    done < <(find "$dir" -maxdepth 4 \
      -path '*/node_modules' -prune -o \
      -name 'package.json' -print 2>/dev/null)
  done

  if [[ $found -gt 0 ]]; then
    detail "Review these scripts — not all are malicious, but verify unknown commands"
    record "postinstall" "⚠️"
  else
    pass "No suspicious install scripts found"
    record "postinstall" "✅"
  fi
}

# 14. Propagation artifacts (.bat files)
check_propagation_artifacts() {
  header "Propagation artifacts (.bat files, .gitignore entries)"
  [[ ${#RESOLVED_DIRS[@]} -eq 0 ]] && { pass "No directories to scan"; record "Propagation" "⏭️"; return; }

  local found=0

  for dir in "${RESOLVED_DIRS[@]}"; do
    local bats
    bats=$(find "$dir" -maxdepth "$MAX_DEPTH" \
      -path '*/node_modules' -prune -o \
      \( -name 'temp_auto_push.bat' -o -name 'config.bat' \) \
      -print 2>/dev/null || true)
    if [[ -n "$bats" ]]; then
      echo "$bats" | while IFS= read -r f; do
        warn "Propagation artifact: $f"
        found=$((found + 1))
      done
    fi
  done

  local gitignore_refs
  gitignore_refs=$(grep -rl $GREP_EXCLUDES \
    --include='.gitignore' \
    'config\.bat' \
    "${RESOLVED_DIRS[@]}" 2>/dev/null || true)
  if [[ -n "$gitignore_refs" ]]; then
    echo "$gitignore_refs" | while IFS= read -r f; do
      warn "config.bat in .gitignore: $f"
      found=$((found + 1))
    done
  fi

  if [[ $found -eq 0 ]]; then
    pass "No propagation artifacts found"
    record "Propagation" "✅"
  else
    record "Propagation" "⚠️"
  fi
}

# 15. Megalodon GitHub Actions injection
check_megalodon_actions() {
  header "Megalodon GitHub Actions injection"
  [[ ${#RESOLVED_DIRS[@]} -eq 0 ]] && { pass "No directories to scan"; record "GH Actions" "⏭️"; return; }

  local found=0
  for dir in "${RESOLVED_DIRS[@]}"; do
    while IFS= read -r workflow; do
      [[ -z "$workflow" ]] && continue
      if grep -qE 'curl\s.*\|\s*(sh|bash)|wget\s.*\|\s*(sh|bash)|base64\s+(-d|--decode)\s*\||\beval\s+\$\(' "$workflow" 2>/dev/null; then
        warn "Suspicious pattern in: $workflow"
        found=$((found + 1))
      fi
    done < <(find "$dir" -maxdepth "$MAX_DEPTH" \
      -path '*/.github/workflows' -type d -exec find {} \( -name '*.yml' -o -name '*.yaml' \) \; 2>/dev/null)
  done

  if [[ $found -gt 0 ]]; then
    detail "Review these workflows — curl|bash and base64 decode in Actions are red flags"
    record "GH Actions" "⚠️"
  else
    pass "No suspicious GitHub Actions patterns found"
    record "GH Actions" "✅"
  fi
}

# 16. Git hooks — hijacked global hooks
check_git_hooks() {
  header "Git hooks integrity"
  local found=0

  local hooks_path
  hooks_path=$(git config --global core.hooksPath 2>/dev/null || true)
  if [[ -n "$hooks_path" ]]; then
    warn "Global hooks path is set: $hooks_path"
    if [[ -d "$hooks_path" ]]; then
      detail "Contents: $(ls "$hooks_path" 2>/dev/null || echo '(empty)')"
    fi
    found=$((found + 1))
  else
    pass "No global hooksPath override"
  fi

  for hook_dir in "$HOME/.config/git/hooks" "$HOME/.git-templates/hooks"; do
    if [[ -d "$hook_dir" ]] && [[ -n "$(ls -A "$hook_dir" 2>/dev/null)" ]]; then
      warn "Hook templates found in: $hook_dir"
      detail "$(ls "$hook_dir")"
      found=$((found + 1))
    fi
  done

  if [[ $found -eq 0 ]]; then
    record "Git hooks" "✅"
  else
    detail "Verify these hooks are legitimate — malware uses global hooks for persistence"
    record "Git hooks" "⚠️"
  fi
}

# 17. npm auth tokens (.npmrc) — existence check only, NEVER print values
check_npmrc_tokens() {
  header "npm auth tokens (.npmrc)"
  local npmrc="$HOME/.npmrc"
  if [[ -f "$npmrc" ]]; then
    local token_lines
    token_lines=$(grep -E '(authToken|_auth|_password)' "$npmrc" 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$token_lines" -gt 0 ]]; then
      warn ".npmrc contains $token_lines line(s) with auth tokens"
      detail "If compromised, rotate these tokens immediately"
      detail "Token values intentionally hidden — inspect manually: cat ~/.npmrc"
      record ".npmrc tokens" "⚠️"
    else
      pass ".npmrc exists but contains no auth tokens"
      record ".npmrc tokens" "✅"
    fi
  else
    pass "No .npmrc file found"
    record ".npmrc tokens" "✅"
  fi
}

# 18. Global packages inventory
check_global_packages() {
  header "Global packages (npm/pnpm)"

  # Resolve the real npm/pnpm binaries to avoid shell lazy-loaders (nvm/oh-my-zsh)
  local npm_bin pnpm_bin
  npm_bin=$(command -v npm 2>/dev/null || true)
  # If npm is a shell function (lazy-loader), try the nvm default path
  if [[ -z "$npm_bin" ]] || type npm 2>/dev/null | head -1 | grep -q "function"; then
    local nvm_npm="${NVM_DIR:-$HOME/.nvm}/versions/node/$(ls "${NVM_DIR:-$HOME/.nvm}/versions/node/" 2>/dev/null | sort -V | tail -1)/bin/npm"
    [[ -x "$nvm_npm" ]] && npm_bin="$nvm_npm"
  fi

  if [[ -n "$npm_bin" && -x "$npm_bin" ]]; then
    printf "       ${DIM}npm global:${NC}\n"
    "$npm_bin" ls -g --depth=0 2>/dev/null | tail -n +2 | while IFS= read -r line; do detail "$line"; done
  else
    detail "npm not found — skipped"
  fi

  pnpm_bin=$(which pnpm 2>/dev/null || true)
  if [[ -z "$pnpm_bin" ]]; then
    # Try common corepack/nvm paths
    local nvm_pnpm="${NVM_DIR:-$HOME/.nvm}/versions/node/$(ls "${NVM_DIR:-$HOME/.nvm}/versions/node/" 2>/dev/null | sort -V | tail -1)/bin/pnpm"
    [[ -x "$nvm_pnpm" ]] && pnpm_bin="$nvm_pnpm"
  fi

  if [[ -n "$pnpm_bin" && -x "$pnpm_bin" ]]; then
    printf "       ${DIM}pnpm global:${NC}\n"
    "$pnpm_bin" ls -g 2>/dev/null | tail -n +2 | while IFS= read -r line; do detail "$line"; done
  else
    detail "pnpm not found — skipped"
  fi

  pass "Review the lists above for any unfamiliar packages"
  record "Global packages" "👀"
}

# 19. VS Code / Cursor extensions
check_extensions() {
  header "Editor extensions"
  local exts=""
  if command -v code &>/dev/null; then
    printf "       ${DIM}VS Code extensions:${NC}\n"
    exts=$(code --list-extensions 2>/dev/null || true)
  elif command -v cursor &>/dev/null; then
    printf "       ${DIM}Cursor extensions:${NC}\n"
    exts=$(cursor --list-extensions 2>/dev/null || true)
  fi

  if [[ -n "$exts" ]]; then
    echo "$exts" | while IFS= read -r ext; do detail "$ext"; done
    pass "Review for unfamiliar extensions"
  else
    pass "No editor extensions found (or editor CLI not available)"
  fi
  record "Extensions" "👀"
}

# 20. Persistence mechanisms
check_persistence() {
  header "Persistence mechanisms"
  local found=0

  if [[ "$(uname)" == "Darwin" ]]; then
    local agents_dir="$HOME/Library/LaunchAgents"
    if [[ -d "$agents_dir" ]] && [[ -n "$(ls -A "$agents_dir" 2>/dev/null)" ]]; then
      printf "       ${DIM}LaunchAgents:${NC}\n"
      ls "$agents_dir" 2>/dev/null | while IFS= read -r f; do detail "$f"; done
    else
      detail "LaunchAgents: (empty)"
    fi
  fi

  local cron
  cron=$(crontab -l 2>/dev/null || true)
  if [[ -n "$cron" ]]; then
    printf "       ${DIM}Crontab:${NC}\n"
    echo "$cron" | while IFS= read -r line; do detail "$line"; done
  else
    detail "Crontab: (empty)"
  fi

  printf "       ${DIM}Suspicious processes (node/npm/python, excluding IDE):${NC}\n"
  local procs
  procs=$(ps aux 2>/dev/null | grep -iE 'node|npm|npx|python' | \
    grep -viE 'grep|Claude|cursor|vscode|Code Helper|Electron|copilot|eslint_d' || true)
  if [[ -n "$procs" ]]; then
    echo "$procs" | while IFS= read -r line; do detail "$line"; done
    # Check for known malware patterns in process list
    if echo "$procs" | grep -qE "_\\\$_[a-f0-9]{4}|_0x[a-f0-9]{4}|global\['|node -e.*global|__DAEMONIZED" 2>/dev/null; then
      fail "MALWARE PROCESS DETECTED — obfuscated code in running process"
      found=$((found + 1))
    fi
  else
    detail "(none)"
  fi

  # VS Code / Cursor payload drops (BeaverTail staging)
  for payload_dir in "$HOME/.vscode" "$HOME/.cursor" "$HOME/.windsurf" "$HOME/.pearai"; do
    for payload in "f.js" "test.js"; do
      if [[ -f "$payload_dir/$payload" ]]; then
        warn "Payload drop found: $payload_dir/$payload"
        detail "$(ls -la "$payload_dir/$payload" 2>/dev/null)"
        found=$((found + 1))
      fi
    done
  done

  # RAT binary drop
  if [[ -f "/tmp/0001.dat" ]]; then
    fail "RAT BINARY DROP: /tmp/0001.dat"
    detail "$(ls -la /tmp/0001.dat 2>/dev/null)"
    found=$((found + 1))
  fi

  if [[ $found -gt 0 ]]; then
    record "Persistence" "🔴"
  else
    pass "Review items above for anything unexpected"
    record "Persistence" "👀"
  fi
}

# 21. Embedded scanning tool binaries (trojaned trufflehog, etc.)
check_embedded_tools() {
  header "Embedded scanning tool binaries"
  [[ ${#RESOLVED_DIRS[@]} -eq 0 ]] && { pass "No directories to scan"; record "Embedded tools" "⏭️"; return; }

  local found=0
  for dir in "${RESOLVED_DIRS[@]}"; do
    local hits
    hits=$(find "$dir" -maxdepth "$MAX_DEPTH" \
      -path '*/node_modules' -prune -o \
      -path '*/.git' -prune -o \
      \( -name 'trufflehog*' -o -name 'gitleaks*' -o -name 'detect-secrets*' \) \
      -type f -print 2>/dev/null || true)
    if [[ -n "$hits" ]]; then
      echo "$hits" | while IFS= read -r f; do
        warn "Embedded scanning tool: $f"
        detail "$(ls -la "$f" 2>/dev/null)"
        found=$((found + 1))
      done
    fi
  done

  if [[ $found -eq 0 ]]; then
    pass "No embedded scanning tool binaries"
    record "Embedded tools" "✅"
  else
    detail "Committed scanning binaries could be trojaned — verify provenance"
    record "Embedded tools" "⚠️"
  fi
}

# 22. createRequire(import.meta.url) in application code
check_create_require() {
  header "createRequire(import.meta) in application code"
  [[ ${#RESOLVED_DIRS[@]} -eq 0 ]] && { pass "No directories to scan"; record "createRequire" "⏭️"; return; }

  local hits
  hits=$(grep -rl $GREP_EXCLUDES \
    --include='*.js' --include='*.mjs' --include='*.ts' \
    -E "createRequire\(import\.meta" \
    "${RESOLVED_DIRS[@]}" 2>/dev/null || true)

  if [[ -n "$hits" ]]; then
    local suspicious=0
    echo "$hits" | while IFS= read -r f; do
      if echo "$f" | grep -qiE '\.config\.|scripts/|bin/|cli|build|webpack|rollup|vite|esbuild|tsup'; then
        detail "Expected (tooling): $f"
      else
        warn "Suspicious createRequire: $f"
        suspicious=$((suspicious + 1))
      fi
    done
    if [[ $suspicious -eq 0 ]]; then
      pass "createRequire found only in expected tooling files"
      record "createRequire" "✅"
    else
      detail "createRequire can load native binaries or bypass ESM — verify usage"
      record "createRequire" "⚠️"
    fi
  else
    pass "No createRequire(import.meta) found"
    record "createRequire" "✅"
  fi
}

# 23. SSH key audit (opt-in: --ssh)
check_ssh_keys() {
  header "SSH key audit (~/.ssh)"
  local ssh_dir="$HOME/.ssh"

  if [[ ! -d "$ssh_dir" ]]; then
    pass "~/.ssh does not exist"
    record "SSH keys" "✅"
    return
  fi

  local found=0

  # Permission checks only on Linux/macOS
  if [[ "$OSTYPE" != msys* && "$OSTYPE" != cygwin* && "$OSTYPE" != win32* ]]; then
    local dir_perms
    dir_perms=$(stat -f '%Lp' "$ssh_dir" 2>/dev/null || stat -c '%a' "$ssh_dir" 2>/dev/null || echo "unknown")

    if [[ "$dir_perms" != "700" ]] && [[ "$dir_perms" != "unknown" ]]; then
      warn "~/.ssh permissions are $dir_perms (expected 700)"
      found=$((found + 1))
    else
      pass "~/.ssh permissions: $dir_perms"
    fi
  else
    detail "Skipping Unix permission check on Windows"
  fi

  # authorized_keys
  if [[ -r "$ssh_dir/authorized_keys" ]]; then
    local key_count
    key_count=$(grep -cve '^\s*$' "$ssh_dir/authorized_keys" 2>/dev/null || echo "0")
    detail "authorized_keys: $key_count key(s)"

    ssh-keygen -lf "$ssh_dir/authorized_keys" 2>/dev/null | while IFS= read -r line; do
      detail "  $line"
    done
  elif [[ -f "$ssh_dir/authorized_keys" ]]; then
    warn "authorized_keys exists but cannot be read"
    found=$((found + 1))
  fi

  # Recent modification check
  detail "File modification times:"

  # Compute "24 hours ago" epoch — three different date flavours:
  #   macOS/BSD  : date -v-24H
  #   Linux/GNU  : date -d '24 hours ago'
  #   Git Bash   : date -d '24 hours ago'  (same as GNU, usually works)
  local recent_threshold
  if [[ "$OSTYPE" == msys* || "$OSTYPE" == cygwin* || "$OSTYPE" == win32* ]]; then
    recent_threshold=$(date -d '24 hours ago' '+%s' 2>/dev/null || echo "0")
  else
    recent_threshold=$(date -v-24H '+%s' 2>/dev/null || date -d '24 hours ago' '+%s' 2>/dev/null || echo "0")
  fi

  while IFS= read -r file; do
    [[ -z "$file" || ! -r "$file" ]] && continue

    local mtime mtime_human

    if [[ "$OSTYPE" == msys* || "$OSTYPE" == cygwin* || "$OSTYPE" == win32* ]]; then
      # Git Bash / MSYS2 / Cygwin — use date -r, avoid broken stat
      mtime=$(date -r "$file" '+%s' 2>/dev/null || echo "0")
      mtime_human=$(date -r "$file" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unknown")
    elif [[ "$(uname)" == "Darwin" ]]; then
      # macOS / BSD stat
      mtime=$(stat -f '%m' "$file" 2>/dev/null || echo "0")
      mtime_human=$(stat -f '%Sm' "$file" 2>/dev/null || echo "unknown")
    else
      # Linux / GNU stat
      mtime=$(stat -c '%Y' "$file" 2>/dev/null || echo "0")
      mtime_human=$(stat -c '%y' "$file" 2>/dev/null || echo "unknown")
    fi

    detail "  $mtime_human  $(basename "$file")"

    if [[ "$mtime" -gt "$recent_threshold" ]] 2>/dev/null; then
      warn "RECENTLY MODIFIED (last 24h): $file"
      found=$((found + 1))
    fi
  done < <(find "$ssh_dir" -maxdepth 1 -type f -readable 2>/dev/null)

  if [[ $found -eq 0 ]]; then
    pass "SSH key state looks normal"
    record "SSH keys" "✅"
  else
    record "SSH keys" "⚠️"
  fi
}

# 24. Known malicious LaunchAgents (trgrip, js-logger-pack)
check_malicious_launchagents() {
  header "Known malicious LaunchAgents"
  if [[ "$(uname)" != "Darwin" ]]; then
    pass "macOS only — skipped"
    record "Malicious LaunchAgents" "⏭️"
    return
  fi
  local agents_dir="$HOME/Library/LaunchAgents"
  local found=0
  if [[ -d "$agents_dir" ]]; then
    IFS='|' read -ra agents <<< "$MALICIOUS_LAUNCHAGENTS"
    for agent in "${agents[@]}"; do
      if [[ -f "$agents_dir/$agent" ]]; then
        fail "MALICIOUS LAUNCHAGENT: $agents_dir/$agent"
        detail "$(ls -la "$agents_dir/$agent" 2>/dev/null)"
        detail "$(cat "$agents_dir/$agent" 2>/dev/null | head -20)"
        found=$((found + 1))
      fi
    done
  fi
  if [[ $found -eq 0 ]]; then
    pass "No known malicious LaunchAgents"
    record "Malicious LaunchAgents" "✅"
  else
    record "Malicious LaunchAgents" "🔴"
  fi
}

# 25. Injected SSH keys (js-logger-pack)
check_injected_ssh_keys() {
  header "Injected SSH keys (known malware keys)"
  local ak="$HOME/.ssh/authorized_keys"
  if [[ ! -f "$ak" ]]; then
    pass "No authorized_keys file"
    record "Injected SSH keys" "✅"
    return
  fi
  local hits
  hits=$(grep -c "$MALICIOUS_SSH_KEY" "$ak" 2>/dev/null || echo "0")
  if [[ "$hits" -gt 0 ]]; then
    fail "MALICIOUS SSH KEY FOUND in authorized_keys ($MALICIOUS_SSH_KEY)"
    detail "This key was injected by js-logger-pack malware"
    detail "Remove it immediately: grep -v '$MALICIOUS_SSH_KEY' ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp && mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys"
    record "Injected SSH keys" "🔴"
  else
    pass "No known malicious SSH keys"
    record "Injected SSH keys" "✅"
  fi
}

# 26. Prototype poisoning / dynamic code execution patterns
check_prototype_poisoning() {
  header "Prototype poisoning & dynamic code execution"
  [[ ${#RESOLVED_DIRS[@]} -eq 0 ]] && { pass "No directories to scan"; record "Prototype poisoning" "⏭️"; return; }
  local hits
  hits=$(grep -rl $GREP_EXCLUDES \
    --include='*.js' --include='*.mjs' --include='*.cjs' --include='*.ts' \
    -E "Transaction\.prototype\.moveCall|Function\.constructor\(\"require\"|Function\.constructor\('require'" \
    "${RESOLVED_DIRS[@]}" 2>/dev/null || true)
  if [[ -n "$hits" ]]; then
    local count
    count=$(echo "$hits" | wc -l | tr -d ' ')
    fail "PROTOTYPE POISONING PATTERNS in $count file(s)"
    echo "$hits" | head -10 | while IFS= read -r f; do detail "$f"; done
    detail "Transaction.prototype override = crypto stealer (crypto-keccak-js pattern)"
    detail "Function.constructor('require') = dynamic C2 dropper (chai-use-chains pattern)"
    record "Prototype poisoning" "🔴"
  else
    pass "No prototype poisoning patterns found"
    record "Prototype poisoning" "✅"
  fi
}

# 27. WASM-based dropper patterns (js-logger-pack)
check_wasm_dropper() {
  header "WASM dropper patterns in install scripts"
  [[ ${#RESOLVED_DIRS[@]} -eq 0 ]] && { pass "No directories to scan"; record "WASM dropper" "⏭️"; return; }
  local found=0
  for dir in "${RESOLVED_DIRS[@]}"; do
    while IFS= read -r file; do
      [[ -z "$file" ]] && continue
      if grep -qE "WebAssembly\.instantiate|WebAssembly\.compile" "$file" 2>/dev/null; then
        if grep -qE "Buffer\.from\(.*base64|atob\(" "$file" 2>/dev/null; then
          warn "WASM + Base64 in: $file"
          found=$((found + 1))
        fi
      fi
    done < <(find "$dir" -maxdepth "$MAX_DEPTH" \
      -path '*/node_modules' -prune -o \
      -path '*/.git' -prune -o \
      \( -name 'print.js' -o -name 'install.js' -o -name 'postinstall.js' -o -name 'preinstall.js' -o -name 'setup.js' \) \
      -print 2>/dev/null)
  done
  if [[ $found -gt 0 ]]; then
    detail "WASM decoded from Base64 in install scripts — js-logger-pack pattern"
    record "WASM dropper" "⚠️"
  else
    pass "No WASM dropper patterns found"
    record "WASM dropper" "✅"
  fi
}

# 28. Known malicious npm accounts in lockfiles
check_malicious_npm_accounts() {
  header "Known malicious npm account references"
  [[ ${#RESOLVED_DIRS[@]} -eq 0 ]] && { pass "No directories to scan"; record "Malicious accounts" "⏭️"; return; }
  local hits
  hits=$(grep -rl $GREP_EXCLUDES \
    --include='pnpm-lock.yaml' --include='package-lock.json' --include='yarn.lock' \
    -E "$MALICIOUS_NPM_ACCOUNTS" \
    "${RESOLVED_DIRS[@]}" 2>/dev/null || true)
  if [[ -n "$hits" ]]; then
    local count
    count=$(echo "$hits" | wc -l | tr -d ' ')
    warn "REFERENCES to known malicious npm accounts in $count lockfile(s)"
    echo "$hits" | while IFS= read -r f; do
      detail "$f"
      grep -oE "$MALICIOUS_NPM_ACCOUNTS" "$f" 2>/dev/null | sort -u | while IFS= read -r acct; do
        detail "  Account: $acct"
      done
    done
    record "Malicious accounts" "⚠️"
  else
    pass "No known malicious npm accounts in lockfiles"
    record "Malicious accounts" "✅"
  fi
}

# ─── Deep checks (macOS only, slow) ──────────────────────────────────────────

check_dns_c2() {
  header "DNS queries to C2 domains (last 7 days, macOS only)"
  printf "       ${DIM}This may take 30-60 seconds...${NC}\n"

  local hits
  hits=$(log show --last 7d --predicate 'process == "mDNSResponder"' --info 2>/dev/null | \
    grep -iE "$C2_DOMAINS|$C2_IPS" | wc -l | tr -d ' ')

  if [[ "$hits" -gt 0 ]]; then
    fail "FOUND $hits DNS queries to C2 domains in the last 7 days"
    log show --last 7d --predicate 'process == "mDNSResponder"' --info 2>/dev/null | \
      grep -iE "$C2_DOMAINS|$C2_IPS" | head -10 | while IFS= read -r line; do detail "$line"; done
    record "DNS to C2" "🔴"
  else
    pass "No DNS queries to known C2 domains"
    record "DNS to C2" "✅"
  fi
}

check_syslog_c2() {
  header "System log C2 references (last 7 days, macOS only)"
  printf "       ${DIM}This may take 30-60 seconds...${NC}\n"

  local hits
  hits=$(log show --last 7d --predicate \
    "eventMessage CONTAINS \"trongrid\" OR \
     eventMessage CONTAINS \"aptoslabs\" OR \
     eventMessage CONTAINS \"166.88.54\" OR \
     eventMessage CONTAINS \"198.105.127\" OR \
     eventMessage CONTAINS \"23.27.202.27\" OR \
     eventMessage CONTAINS \"44.206.172.239\" OR \
     eventMessage CONTAINS \"195.201.194.107\" OR \
     eventMessage CONTAINS \"bsc-dataseed\" OR \
     eventMessage CONTAINS \"api.telegram.org\" OR \
     eventMessage CONTAINS \"default-configuration.vercel\" OR \
     eventMessage CONTAINS \"vscode-settings-bootstrap.vercel\" OR \
     eventMessage CONTAINS \"coingecko-liard.vercel\" OR \
     eventMessage CONTAINS \"jrodacooker\" OR \
     eventMessage CONTAINS \"260120.vercel\"" 2>/dev/null | \
    grep -vE "^Timestamp|^$|^---" | wc -l | tr -d ' ')

  if [[ "$hits" -gt 0 ]]; then
    fail "FOUND $hits system log entries referencing C2"
    record "Syslog C2" "🔴"
  else
    pass "No C2 references in system logs"
    record "Syslog C2" "✅"
  fi
}

# ─── Summary ──────────────────────────────────────────────────────────────────

print_summary() {
  printf "\n"
  printf "══════════════════════════════════════════════════════════════════\n"
  printf " SUMMARY\n"
  printf "══════════════════════════════════════════════════════════════════\n\n"

  printf " %-4s %-35s %s\n" "#" "Check" "Result"
  printf " %-4s %-35s %s\n" "---" "-----------------------------------" "------"
  for i in "${!CHECK_NAMES[@]}"; do
    printf " %-4s %-35s %s\n" "$((i + 1))" "${CHECK_NAMES[$i]}" "${CHECK_RESULTS[$i]}"
  done

  printf "\n"

  if [[ $FINDINGS -gt 0 ]]; then
    printf "══════════════════════════════════════════════════════════════════\n"
    printf " ${RED}${BOLD}%d FINDING(S) — review the details above${NC}\n" "$FINDINGS"
    printf "══════════════════════════════════════════════════════════════════\n"
    printf "\n"
    printf " 🔴 = confirmed compromise indicator. Stop all work, rotate secrets.\n"
    printf " ⚠️  = suspicious, needs manual verification.\n"
    printf " 👀 = informational, review for anything unexpected.\n"
    printf "\n"
    printf " If you see 🔴 findings:\n"
    printf "   1. DO NOT push to any repository\n"
    printf "   2. DO NOT delete evidence files\n"
    printf "   3. Report to your security lead with this output\n"
    printf "   4. Rotate ALL secrets (npm tokens, SSH keys, API keys, .env values)\n"
  else
    printf "══════════════════════════════════════════════════════════════════\n"
    printf " ${GREEN}${BOLD}ALL CLEAR — no compromise indicators found${NC}\n"
    printf "══════════════════════════════════════════════════════════════════\n"
    printf "\n"
    printf " 👀 items above are informational — review them briefly.\n"
    printf " This scan covers known IOCs as of %s.\n" "$VERSION"
    printf " A clean scan does not guarantee absence of novel threats.\n"
  fi

  printf "\n"
}

# ─── Main ─────────────────────────────────────────────────────────────────────

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --scan-dirs) SCAN_DIRS="$2"; shift 2 ;;
      -h|--help)
        printf "Usage: %s [--scan-dirs \"/path/a /path/b\"]\n" "$0"
        printf "  --scan-dirs    Override source code directories to scan\n"
        exit 0
        ;;
      *) printf "Unknown option: %s\n" "$1"; exit 1 ;;
    esac
  done
}

main() {
  parse_args "$@"

  printf "══════════════════════════════════════════════════════════════════\n"
  printf " Supply Chain Malware Scanner v%s\n" "$VERSION"
  printf " PolinRider / InvisibleFerret / Megalodon\n"
  printf "══════════════════════════════════════════════════════════════════\n"
  printf "\n"
  printf " Platform:   %s %s\n" "$(uname -s)" "$(uname -m)"
  printf " User:       %s\n" "$(whoami)"
  printf " Date:       %s\n" "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

  resolve_dirs
  if [[ ${#RESOLVED_DIRS[@]} -gt 0 ]]; then
    printf " Scan dirs:  %s\n" "${RESOLVED_DIRS[*]}"
  else
    printf " Scan dirs:  (none found)\n"
  fi

  # Core IOCs
  check_lock_file
  check_credential_dumps
  check_network_c2
  check_invisibleferret

  # Source code infection
  check_malware_signatures
  check_long_config_lines
  check_fake_fonts
  check_malicious_packages
  check_vscode_tasks
  check_solana_c2

  # Supply chain
  check_axios_compromised
  check_nx_console
  check_postinstall_scripts

  # Propagation
  check_propagation_artifacts
  check_megalodon_actions

  # Environment integrity
  check_git_hooks
  check_npmrc_tokens
  check_global_packages
  check_extensions
  check_persistence

  # Additional checks (v1.1)
  check_embedded_tools
  check_create_require
  check_ssh_keys

  # New checks (v1.2 — indece report 2026-04)
  check_malicious_launchagents
  check_injected_ssh_keys
  check_prototype_poisoning
  check_wasm_dropper
  check_malicious_npm_accounts

  # Deep checks (macOS only, slow)
  if [[ "$(uname)" == "Darwin" ]]; then
    check_dns_c2
    check_syslog_c2
  fi

  print_summary

  if [[ $FINDINGS -gt 0 ]]; then
    exit 1
  else
    exit 0
  fi
}

main "$@"