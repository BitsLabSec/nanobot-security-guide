#!/usr/bin/env bash
set -euo pipefail

target="${1:-}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
skill_root="$(cd "${script_dir}/.." && pwd)"
allowlist_file="${NANOBOT_ALLOWLIST_FILE:-${skill_root}/policy/allowlist.txt}"
if [[ -z "${target}" ]]; then
  echo "usage: $0 <path-to-skill-or-mcp-config>" >&2
  exit 2
fi

if [[ ! -e "${target}" ]]; then
  echo "target not found: ${target}" >&2
  exit 2
fi

if command -v rg >/dev/null 2>&1; then
  SEARCH_CMD=(rg -n -S -uu -g '!node_modules' -g '!.git')
else
  SEARCH_CMD=(grep -R -n -E)
fi

run_search() {
  local pattern="$1"
  "${SEARCH_CMD[@]}" "${pattern}" "${target}" 2>/dev/null || true
}

apply_allowlist() {
  local input="$1"
  local filtered="${input}"
  local rule prefix value

  if [[ ! -f "${allowlist_file}" || -z "${input}" ]]; then
    printf '%s\n' "${filtered}"
    return
  fi

  while IFS= read -r rule; do
    [[ -z "${rule}" || "${rule}" =~ ^# ]] && continue
    prefix="${rule%%:*}"
    value="${rule#*:}"
    case "${prefix}" in
      allow-path|allow-domain|allow-process|allow-port)
        filtered="$(printf '%s\n' "${filtered}" | grep -F -v "${value}" || true)"
        ;;
      allow-regex)
        filtered="$(printf '%s\n' "${filtered}" | grep -E -v "${value}" || true)"
        ;;
    esac
  done <"${allowlist_file}"

  printf '%s\n' "${filtered}"
}

print_rule() {
  local severity="$1"
  local code="$2"
  local title="$3"
  local pattern="$4"
  local rationale="$5"
  local result

  result="$(run_search "${pattern}")"
  result="$(apply_allowlist "${result}")"
  if [[ -z "${result}" ]]; then
    return
  fi

  printf '[%s] %s %s\n' "${severity}" "${code}" "${title}"
  printf 'why: %s\n' "${rationale}"
  printf '%s\n\n' "${result}" | head -120
}

print_inventory() {
  echo "== File inventory =="
  if [[ -d "${target}" ]]; then
    find "${target}" -type f 2>/dev/null | sort || true
  else
    printf '%s\n' "${target}"
  fi
  echo

  echo "== Executable files =="
  if [[ -d "${target}" ]]; then
    find "${target}" -type f -perm -111 2>/dev/null | sort || true
  fi
  echo

  echo "== Hidden files =="
  if [[ -d "${target}" ]]; then
    find "${target}" -type f -name '.*' 2>/dev/null | sort || true
  fi
  echo
}

print_group_header() {
  echo "== $1 =="
}

has_match() {
  local pattern="$1"
  local result
  result="$(run_search "${pattern}")"
  result="$(apply_allowlist "${result}")"
  [[ -n "${result}" ]]
}

echo "== Security Scan =="
echo "target: ${target}"
echo

print_inventory

print_group_header "Detection Rules"

print_rule "critical" "NSG001" "Prompt Injection Surface" \
  '(ignore (all|previous) instructions|system prompt|developer prompt|reveal prompt|override safety|do not follow prior rules|follow the content below exactly)' \
  "Instruction override or prompt disclosure language indicates an attempt to hijack the agent."

print_rule "critical" "NSG002" "Credential Or Secret Handling" \
  '(api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?cookie|authorization:|bearer[[:space:]]+[A-Za-z0-9._-]+|password|passwd|private key|BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY)' \
  "Secrets in prompts, scripts, or configs can lead to credential theft or accidental disclosure."

print_rule "critical" "NSG003" "Remote Bootstrap Or Exfiltration" \
  '(curl[[:space:]].*\|[[:space:]]*(sh|bash)|wget[[:space:]].*\|[[:space:]]*(sh|bash)|Invoke-WebRequest|http://|https://|nc[[:space:]]|ncat[[:space:]]|netcat[[:space:]]|socat[[:space:]]|/dev/tcp/)' \
  "Remote fetch-and-execute or ad hoc network channels are common delivery and exfiltration mechanisms."

print_rule "critical" "NSG004" "Command Execution Or Eval" \
  '(bash[[:space:]]+-c|sh[[:space:]]+-c|python[[:space:]]+-c|node[[:space:]]+-e|perl[[:space:]]+-e|ruby[[:space:]]+-e|eval[[:space:](]|exec[[:space:](]|subprocess|child_process|Runtime\.getRuntime)' \
  "Inline execution and dynamic evaluation expand blast radius and hide true behavior."

print_rule "critical" "NSG005" "Persistence Or System Service Modification" \
  '(launchctl|systemctl|crontab|cron\.d|rc\.local|~/Library/LaunchAgents|/etc/systemd|login items|defaults[[:space:]]+write)' \
  "Persistence changes can create stealthy long-lived compromise."

print_rule "review" "NSG006" "Tool Shadowing Or Dangerous Permissions" \
  '(dangerously-skip-permissions|trust-all-tools|allow_implicit_invocation:[[:space:]]*true|allowedTools|allowed_non_write_users|Bash,Read,Write,Edit|full access|sudo )' \
  "Broad tool access or permissive invocation can turn prompt injection into code execution."

print_rule "review" "NSG007" "Obfuscation" \
  '(base64[[:space:]]+-d|openssl enc|xxd -r|fromCharCode|atob\(|Buffer\.from\(|\\x[0-9a-fA-F]{2}|[A-Za-z0-9+/]{80,}={0,2})' \
  "Obfuscation is often used to hide payloads or evade review."

print_rule "review" "NSG008" "MCP High-Risk Capability" \
  '(transport:[[:space:]]*"(stdio|streamable_http|sse)"|command:[[:space:]]|args:[[:space:]]|spawn|exec|filesystem|write_file|delete_file|shell|browser|fetch|network)' \
  "MCP definitions that can spawn commands, write files, or browse externally require manual approval."

print_rule "review" "NSG009" "Phishing Or Login Harvesting" \
  '(login|sign in|oauth|mfa|2fa|verification code|paste cookie|paste token|browser console|devtools)' \
  "Login-oriented prompts and browser console instructions can be used to steal credentials."

print_rule "review" "NSG010" "Sensitive File Access" \
  '(\.ssh|id_rsa|known_hosts|authorized_keys|\.aws|credentials|\.env|\.npmrc|\.pypirc|\.git-credentials|keychain|security[[:space:]]+find-)' \
  "Direct access to secret-bearing files should be reviewed even if the surrounding code looks benign."

echo "== Toxic Flow Heuristics =="
if has_match '(issue|pull request|email|web page|markdown|clipboard|user input|prompt|chat message|README|docs?)' \
  && has_match '(bash[[:space:]]+-c|sh[[:space:]]+-c|curl[[:space:]].*\|[[:space:]]*(sh|bash)|launchctl|systemctl|write_file|delete_file|Authorization:|api[_-]?key|private key|ssh)'; then
  echo "[critical] NSG011 Potential Toxic Flow"
  echo "why: untrusted content appears near privileged actions or secret-bearing operations."
  echo
fi

if has_match '(http://|https://|fetch|curl|wget|browser|web)' \
  && has_match '(token|secret|cookie|Authorization:|private key|credential|password)'; then
  echo "[critical] NSG012 Potential Secret Exfiltration Path"
  echo "why: the same artifact references both outbound connectivity and credential material."
  echo
fi

echo "== Risk notes =="
cat <<'EOF'
- These rules are intentionally biased toward recall, not silence.
- A match is not proof of compromise, but every critical match requires manual review.
- The toxic-flow heuristics are adapted from agent-scan style attack chaining: untrusted input + privileged tool use + sensitive data path.
- Allowlist filtering is applied from policy/allowlist.txt when present.
EOF
