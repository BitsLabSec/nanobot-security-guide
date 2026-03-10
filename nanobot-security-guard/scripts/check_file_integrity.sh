#!/usr/bin/env bash

# nanobot-security-guard: File Integrity Monitoring (Hash Baseline)
# Periodically verify the integrity of critical configuration, memory, and skill files.

set -e

BASELINE_FILE="${HOME}/.nanobot/security_baseline.sha256"

# List of critical files to monitor
# Note: SKILL.md files are dynamically found below
CRITICAL_FILES=(
    "${HOME}/.nanobot/config.json"
    "${HOME}/.nanobot/workspace/memory/MEMORY.md"
)

# Add all installed SKILL.md and agent definition files
if [ -d "${HOME}/.nanobot/skills" ]; then
    while IFS= read -r skill_file; do
        CRITICAL_FILES+=("$skill_file")
    done < <(find "${HOME}/.nanobot/skills" -type f \( -name "SKILL.md" -o -name "agent.yaml" -o -name "*.py" -o -name "*.sh" \) 2>/dev/null)
fi

# Function to compute SHA256 (handles macOS and Linux differences)
compute_sha256() {
    local file="$1"
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    else
        echo "UNKNOWN"
    fi
}

echo "[*] Initiating File Integrity Monitoring (FIM)..."

# If baseline doesn't exist, create it
if [ ! -f "$BASELINE_FILE" ]; then
    echo "[!] No baseline found. Establishing new hash baseline at: $BASELINE_FILE"
    > "$BASELINE_FILE"
    for file in "${CRITICAL_FILES[@]}"; do
        if [ -f "$file" ]; then
            hash=$(compute_sha256 "$file")
            echo "${hash}  ${file}" >> "$BASELINE_FILE"
        fi
    done
    echo "[✓] Baseline established successfully."
    exit 0
fi

# Baseline exists, verify files
echo "[*] Comparing current files against baseline: $BASELINE_FILE"

declare -i violations=0
declare -a missing_files
declare -a modified_files

# Check for modified or deleted files against the baseline
while read -r baseline_hash filepath; do
    if [ ! -f "$filepath" ]; then
        missing_files+=("$filepath")
        ((violations++))
    else
        current_hash=$(compute_sha256 "$filepath")
        if [ "$baseline_hash" != "$current_hash" ]; then
            modified_files+=("$filepath")
            ((violations++))
        fi
    fi
done < "$BASELINE_FILE"

# Output results
if [ $violations -eq 0 ]; then
    echo "[✓] INTEGRITY PASS: All critical files match their baseline hashes."
else
    echo "[X] INTEGRITY CHECK FAILED: $violations violations detected!"
    
    if [ ${#missing_files[@]} -gt 0 ]; then
        echo "--- DELETED OR MISSING FILES ---"
        for missing in "${missing_files[@]}"; do
            echo "  [MISSING] $missing"
        done
    fi

    if [ ${#modified_files[@]} -gt 0 ]; then
        echo "--- MODIFIED FILES (POTENTIAL COMPROMISE) ---"
        for modified in "${modified_files[@]}"; do
            echo "  [MODIFIED] $modified"
        done
    fi
    
    echo "=================================================================="
    echo "🚨 ACTION REQUIRED: Investigate these changes immediately."
    echo "If changes were intentional, update the baseline by running:"
    echo "  rm $BASELINE_FILE"
    echo "  bash $0"
    echo "=================================================================="
    exit 1
fi
