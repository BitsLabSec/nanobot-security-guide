#!/usr/bin/env bash
set -euo pipefail

name_filter="${1:-}"
report_path="${TMPDIR:-/tmp}/nanobot-mcp-runtime-$(date '+%Y%m%d-%H%M%S').txt"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
skill_root="$(cd "${script_dir}/.." && pwd)"
allowlist_file="${NANOBOT_ALLOWLIST_FILE:-${skill_root}/policy/allowlist.txt}"
baseline_file="${NANOBOT_BASELINE_FILE:-${skill_root}/policy/runtime-baseline.txt}"

have() {
  command -v "$1" >/dev/null 2>&1
}

emit() {
  printf '%s\n' "${1:-}" >>"${report_path}"
}

section() {
  printf '\n## %s\n' "$1" >>"${report_path}"
}

safe_cmd() {
  "$@" 2>/dev/null || true
}

read_prefixed_values() {
  local file="$1"
  local prefix="$2"
  [[ -f "${file}" ]] || return 0
  grep -E "^${prefix}:" "${file}" 2>/dev/null | sed "s/^${prefix}://"
}

apply_allowlist_stream() {
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

append_baseline_delta() {
  local section_name="$1"
  local current="$2"
  local baseline_prefix="$3"
  local baseline expected line

  baseline="$(read_prefixed_values "${baseline_file}" "${baseline_prefix}" || true)"

  section "${section_name}"
  if [[ -z "${current}" ]]; then
    emit "no signals collected"
    return
  fi

  if [[ -z "${baseline}" ]]; then
    emit "baseline file has no ${baseline_prefix} entries"
    printf '%s\n' "${current}" >>"${report_path}"
    return
  fi

  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    if ! printf '%s\n' "${baseline}" | grep -F -q "${line}"; then
      printf '%s\n' "${line}" >>"${report_path}"
    fi
  done <<<"${current}"
}

collect_config_paths() {
  local candidates=(
    "$PWD"
    "$HOME/.codex"
    "$HOME/.config"
    "$HOME/Library/Application Support"
  )
  local existing=()
  local path
  for path in "${candidates[@]}"; do
    [[ -e "${path}" ]] && existing+=("${path}")
  done

  if [[ ${#existing[@]} -eq 0 ]]; then
    return
  fi

  if have rg; then
    rg -l -S -uu -g '!node_modules' -g '!.git' \
      '(mcp|model context protocol|transport:|streamable_http|stdio|sse|command:|args:)' \
      "${existing[@]}" 2>/dev/null | head -100 || true
  else
    find "${existing[@]}" -type f 2>/dev/null | head -100 || true
  fi
}

filter_stream() {
  if [[ -n "${name_filter}" ]]; then
    grep -Ei "${name_filter}" || true
  else
    cat
  fi
}

{
  printf '# Nanobot MCP Runtime Report\n'
  printf 'generated_at: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
  printf 'host: %s\n' "$(hostname 2>/dev/null || echo unknown-host)"
  printf 'os: %s\n' "$(uname -s 2>/dev/null || echo unknown-os)"
  if [[ -n "${name_filter}" ]]; then
    printf 'filter: %s\n' "${name_filter}"
  fi
} >"${report_path}"

section "MCP Config Candidates"
collect_config_paths >>"${report_path}"

section "MCP Config Snippets"
if have rg; then
  config_candidates="$(collect_config_paths)"
  if [[ -n "${config_candidates}" ]]; then
    while IFS= read -r file; do
      [[ -z "${file}" ]] && continue
      emit "# ${file}"
      rg -n -S '(mcp|transport|streamable_http|stdio|sse|command:|args:|url:|token|secret|key|write|delete|shell|browser|fetch)' "${file}" 2>/dev/null | head -40 >>"${report_path}" || true
      emit ""
    done <<<"${config_candidates}"
  else
    emit "no MCP-like config files found"
  fi
else
  emit "rg unavailable; config snippet extraction skipped"
fi

section "Candidate Processes"
if have ps; then
  if have pgrep; then
    process_output="$({ safe_cmd pgrep -a -f 'mcp|model context protocol|codex|claude|agent|server|stdio|streamable_http' | filter_stream; } || true)"
  else
    process_output="$({ safe_cmd ps aux | grep -Ei 'mcp|model context protocol|codex|claude|agent|server|stdio|streamable_http' | grep -v grep | filter_stream; } || true)"
  fi
  process_output="$(apply_allowlist_stream "${process_output}")"
  printf '%s\n' "${process_output}" >>"${report_path}"
else
  emit "ps unavailable"
fi

section "Open Network Endpoints"
if have lsof; then
  network_output="$({ safe_cmd lsof -nP -iTCP -sTCP:LISTEN | filter_stream | head -120; safe_cmd lsof -nP -iTCP -sTCP:ESTABLISHED | filter_stream | head -120; } || true)"
  network_output="$(apply_allowlist_stream "${network_output}")"
  printf '%s\n' "${network_output}" >>"${report_path}"
elif have netstat; then
  network_output="$({ safe_cmd netstat -an | filter_stream | head -200; } || true)"
  network_output="$(apply_allowlist_stream "${network_output}")"
  printf '%s\n' "${network_output}" >>"${report_path}"
else
  emit "lsof/netstat unavailable"
fi

section "Environment Variable Names"
env | cut -d= -f1 | grep -Ei '(mcp|gateway|proxy|token|secret|key|auth|credential)' | sort -u >>"${report_path}" || true

section "Risk Heuristics"
cat <<'EOF' >>"${report_path}"
critical:
- MCP process exposes external listener on non-loopback interface without documented need
- MCP command line includes credential material, bearer tokens, or plaintext secrets
- MCP server combines outbound network access with write/delete/shell capabilities

review:
- transport is unclear or undocumented
- stdio wrapper launches through shell evaluation
- config references external URLs, browsers, fetch tools, or broad filesystem access
- process name or command line does not match declared MCP identity
EOF

section "High-Risk Config Indicators"
if have rg; then
  config_candidates="$(collect_config_paths)"
  if [[ -n "${config_candidates}" ]]; then
    while IFS= read -r file; do
      [[ -z "${file}" ]] && continue
      result="$(rg -n -S '(Authorization:|Bearer[[:space:]]+[A-Za-z0-9._-]+|token|secret|password|shell|exec|spawn|write|delete|browser|fetch|https?://|stdio|streamable_http|sse)' "${file}" 2>/dev/null | head -60 || true)"
      if [[ -n "${result}" ]]; then
        emit "# ${file}"
        printf '%s\n' "${result}" >>"${report_path}"
        emit ""
      fi
    done <<<"${config_candidates}"
  fi
else
  emit "rg unavailable; high-risk config scan skipped"
fi

section "Operator Notes"
cat <<'EOF' >>"${report_path}"
- Review this report together with scan_artifact.sh output for the same MCP config or wrapper scripts.
- Never trust a benign config name by itself; verify command, args, transport, and endpoint.
- Treat localhost listeners as review items when they bridge to remote systems or can invoke tools with side effects.
- Allowlist filtering comes from policy/allowlist.txt when present.
- Baseline deltas compare against policy/runtime-baseline.txt when present.
EOF

config_summary="$(collect_config_paths | head -50 || true)"
config_summary="$(apply_allowlist_stream "${config_summary}")"
append_baseline_delta "New Config Candidates Vs Baseline" "${config_summary}" "baseline-config"
append_baseline_delta "New Process Signals Vs Baseline" "${process_output:-}" "baseline-process"
append_baseline_delta "New Network Signals Vs Baseline" "${network_output:-}" "baseline-port"

printf '%s\n' "${report_path}"
