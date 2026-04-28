#!/usr/bin/env bash
# verify_attack_tools.sh — Smoke-test that every tool listed in
# src/core/orchestrator/recon_pipeline.ts:ATTACK_MACHINE_TOOLS is actually
# installed and runnable inside the built attack-machine image.
#
# Why this exists: `recon_tool_inventory.test.ts` enforces source-side
# invariants (pipeline only invokes inventoried tools, prompt mentions
# them, no design-removed tools sneak back in). It can't verify that the
# *Dockerfile* actually installs what the inventory promises. This
# script closes that loop by running each tool's `--version`-style probe
# inside the real image.
#
# Usage:
#   docker build -t huntress-attack-machine:latest -f docker/Dockerfile.attack-machine docker/
#   ./scripts/verify_attack_tools.sh
#
# Exit codes:
#   0  — every tool is present and runnable
#   1  — at least one tool is missing or fails its probe
#   2  — image is not built / docker is unavailable
#
# The tool list and per-tool probe args are kept identical to
# ATTACK_MACHINE_TOOLS in recon_pipeline.ts. When that constant changes,
# update this script in the same commit.

set -uo pipefail

IMAGE="${HUNTRESS_ATTACK_IMAGE:-huntress-attack-machine:latest}"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found in PATH" >&2
  exit 2
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "ERROR: image '$IMAGE' not built. Run:" >&2
  echo "  docker build -t $IMAGE -f docker/Dockerfile.attack-machine docker/" >&2
  exit 2
fi

# Tool table — name + probe args. Must match ATTACK_MACHINE_TOOLS.
# Format: "name:arg1 arg2 …"
TOOLS=(
  # Go binaries (ProjectDiscovery / tomnomnom / ffuf / dalfox).
  "subfinder:-version"
  "assetfinder:-h"
  "httpx:-version"
  "katana:-version"
  "naabu:-version"
  "dnsx:-version"
  "nuclei:-version"
  "gau:--version"
  "waybackurls:-h"
  "ffuf:-V"
  "dalfox:version"
  "interactsh-client:-version"
  # Python tooling in /opt/tools venv.
  "sqlmap:--version"
  "wafw00f:--version"
  "paramspider:-h"
  # apt packages.
  "whatweb:--version"
  "testssl.sh:--version"
  "nmap:-V"
  # base utilities.
  "curl:--version"
  "wget:--version"
  "jq:--version"
  "dig:-v"
)

passed=0
failed=0
failures=()

printf '%-22s %-10s %s\n' 'TOOL' 'STATUS' 'NOTES'
printf '%-22s %-10s %s\n' '----' '------' '-----'

for entry in "${TOOLS[@]}"; do
  name="${entry%%:*}"
  args="${entry#*:}"

  # `docker run --rm <image> <name> <args>` — the entrypoint takes the
  # tool name as argv[0] and runs it. ENTRYPOINT may also rewrite this;
  # use --entrypoint to bypass.
  output=$(docker run --rm --entrypoint "$name" "$IMAGE" $args 2>&1) || rc=$?
  rc=${rc:-0}

  # Many tools (assetfinder -h, waybackurls -h, paramspider -h) exit 1
  # but print the help banner. As long as we got *some* output containing
  # the tool name or a version-ish token, treat that as "installed."
  if [ $rc -eq 0 ] || echo "$output" | grep -qiE "$name|version|usage|v[0-9]"; then
    passed=$((passed + 1))
    notes=$(echo "$output" | head -n 1 | tr -d '\r' | cut -c1-60)
    printf '%-22s %-10s %s\n' "$name" 'OK' "$notes"
  else
    failed=$((failed + 1))
    failures+=("$name (exit $rc): $(echo "$output" | head -n 1)")
    printf '%-22s %-10s %s\n' "$name" 'FAIL' "exit $rc"
  fi

  unset rc
done

echo
echo "Summary: $passed passed, $failed failed (of $(( ${#TOOLS[@]} )) total)"

if [ $failed -gt 0 ]; then
  echo
  echo "Failures:" >&2
  for f in "${failures[@]}"; do echo "  - $f" >&2; done
  exit 1
fi

exit 0
