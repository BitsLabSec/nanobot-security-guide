#!/usr/bin/env bash
set -euo pipefail

timestamp="$(date '+%Y-%m-%d %H:%M:%S %Z')"
host="$(hostname 2>/dev/null || echo unknown-host)"
os_name="$(uname -s 2>/dev/null || echo unknown-os)"
tmp_report="${TMPDIR:-/tmp}/nanobot-security-report-$(date '+%Y%m%d-%H%M%S').txt"

have() {
  command -v "$1" >/dev/null 2>&1
}

section() {
  printf '\n## %s\n' "$1" >>"${tmp_report}"
}

emit() {
  printf '%s\n' "${1:-}" >>"${tmp_report}"
}

redact_env_names() {
  env | cut -d= -f1 | grep -Ei '(gateway|proxy|token|secret|key|passwd|password|credential|auth)' | sort -u || true
}

scan_sensitive_changes() {
  local paths=()
  for p in \
    "$HOME/.ssh" \
    "$HOME/.aws" \
    "$HOME/.config" \
    "$HOME/.codex" \
    "$HOME/.gnupg" \
    "$PWD"
  do
    [[ -e "$p" ]] && paths+=("$p")
  done

  if [[ ${#paths[@]} -eq 0 ]]; then
    echo "no tracked sensitive paths found"
    return
  fi

  find "${paths[@]}" -type f -mtime -1 2>/dev/null | sort | head -200 || true
}

scan_plaintext_exposure() {
  local paths=()
  for p in "$PWD" "$HOME/.ssh" "$HOME/.config" "$HOME/.codex"; do
    [[ -e "$p" ]] && paths+=("$p")
  done

  if [[ ${#paths[@]} -eq 0 ]]; then
    echo "no scan paths found"
    return
  fi

  if have rg; then
    rg -n -S -uu -g '!node_modules' -g '!.git' \
      '(BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN PGP PRIVATE KEY BLOCK-----)' \
      "${paths[@]}" 2>/dev/null | head -200 || true
  else
    echo "rg not available; plaintext exposure scan skipped"
  fi
}

{
  printf '# Nanobot Nightly Security Report\n'
  printf 'generated_at: %s\n' "${timestamp}"
  printf 'host: %s\n' "${host}"
  printf 'os: %s\n' "${os_name}"
} >"${tmp_report}"

section "Summary"
emit "This report is read-only. Review flagged paths and commands before taking action."

section "Recent Processes"
if have ps; then
  if ! ps aux 2>/dev/null | head -40 >>"${tmp_report}"; then
    emit "ps available but blocked by current runtime permissions"
  fi
else
  emit "ps unavailable"
fi

section "Network Activity"
if have lsof; then
  emit "# listeners and established connections"
  lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | head -100 >>"${tmp_report}" || true
  lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | head -100 >>"${tmp_report}" || true
elif have netstat; then
  netstat -an 2>/dev/null | head -200 >>"${tmp_report}" || true
else
  emit "lsof/netstat unavailable"
fi

section "Sensitive Directory Changes (<24h)"
scan_sensitive_changes >>"${tmp_report}"

section "Login And SSH Signals"
if have last; then
  last -n 20 >>"${tmp_report}" 2>/dev/null || true
else
  emit "last unavailable"
fi

section "Disk Usage"
if have df; then
  df -h >>"${tmp_report}" 2>/dev/null || true
else
  emit "df unavailable"
fi
if have du; then
  emit ""
  emit "# workspace size"
  du -sh "$PWD" 2>/dev/null >>"${tmp_report}" || true
fi

section "Sensitive Environment Variable Names"
redact_env_names >>"${tmp_report}"

section "Plaintext Credential Indicators"
scan_plaintext_exposure >>"${tmp_report}"

section "Manual Review Guidance"
cat <<'EOF' >>"${tmp_report}"
ok:
- expected processes, expected listeners, no unusual recent changes

review:
- new network peers, unexpected edits under sensitive paths, env names indicating secret sprawl

critical:
- plaintext private keys, access tokens, unexplained login activity, unknown listeners, or credential-like data in workspace files
EOF

printf '%s\n' "${tmp_report}"
