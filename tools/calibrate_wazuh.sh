#!/usr/bin/env bash
# One-time MiniWazuh fidelity calibration (NOT run in CI; needs Docker).
#
# MiniWazuh (src/iris/synth/soc/miniwazuh.py) reimplements a subset of the Wazuh analysis
# pipeline. Its fidelity is UNVERIFIED until this script compares its verdicts against real
# `wazuh-logtest` on the pinned 4.14.9 ruleset for a corpus of emitted raw lines.
#
# Usage:
#   tools/calibrate_wazuh.sh path/to/raw_lines.txt
#
# It runs each line through the official wazuh-logtest in the wazuh/wazuh-manager:4.14.9 image
# and writes a report of (line -> real rule id/level) vs (line -> MiniWazuh rule id/level).
# Investigate every mismatch; record systematic gaps in docs/UNSUPPORTED_RULES.md. Do NOT weaken
# MiniWazuh to match — fix the decoder/rule handling or mark the construct unsupported.
set -euo pipefail

CORPUS="${1:?usage: calibrate_wazuh.sh <raw_lines.txt>}"
IMAGE="wazuh/wazuh-manager:4.14.9"
OUT="${OUT:-wazuh_calibration_report.txt}"

echo "Running real wazuh-logtest ($IMAGE) over $CORPUS ..."
while IFS= read -r line; do
  printf '%s\n' "$line" | docker run --rm -i "$IMAGE" /var/ossec/bin/wazuh-logtest -q 2>/dev/null \
    | awk -v l="$line" '/Rule id/{rid=$NF} /Level/{lvl=$NF} END{printf "%s\tREAL rule=%s level=%s\n", l, rid, lvl}'
done < "$CORPUS" > "$OUT"

echo "Wrote $OUT. Compare against MiniWazuh with:"
echo "  PYTHONPATH=src python -m iris.synth.soc.miniwazuh_calibrate $CORPUS  # (add a small driver)"
