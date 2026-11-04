#!/usr/bin/env bash
# build_final_dataset.sh — seal the IRIS context/GRC dataset into a release folder.
# Docker-free. Produces: packages + baseline score + MANIFEST.json + DATASHEET.md.
#
#   ./build_final_dataset.sh [COUNT]      (default 1000)
#
# Reproducible by design: same seeds -> same bytes. The manifest records the
# generator version + seed range, which is all anyone needs to rebuild it.
set -euo pipefail

COUNT="${1:-1000}"
IRIS="${IRIS:-uv run iris}"
# Pin the provenance timestamp so the hidden manifests are byte-identical too
# (reproducible-builds convention, honoured by iris.core.vclock.provenance_utc_now).
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1767225600}"   # 2026-01-01T00:00:00Z
STORE="${IRIS_STORE:-/srv/iris/store/context}"
STAMP="$(date +%Y%m%d-%H%M)"
REL="releases/iris-dataset-${STAMP}"

G=$'\e[32m'; R=$'\e[31m'; C=$'\e[36m'; B=$'\e[1m'; X=$'\e[0m'
step(){ printf '\n%s▸ %s%s\n' "$C$B" "$*" "$X"; }
die(){ printf '%s✗ %s%s\n' "$R" "$*" "$X"; exit 1; }
trap 'die "build failed above — nothing sealed, fix the error and re-run"' ERR

mkdir -p "$REL"

step "1/6  Repository gate (make check)"
make check
printf '%s✓ tree green%s\n' "$G" "$X"

step "2/6  Generate + verify ${COUNT} context packages"
$IRIS package batch --count "$COUNT" --out "$STORE"

step "3/6  Independent verify pass (hashes, Merkle, no-peek audit)"
n=0; bad=0
while IFS= read -r d; do
  [ -f "$d/manifest.visible.json" ] || continue; n=$((n+1))
  $IRIS package verify "$d" >/dev/null 2>&1 || { bad=$((bad+1)); printf '%s✗ %s%s\n' "$R" "$(basename "$d")" "$X"; }
done < <(find "$STORE" -maxdepth 1 -mindepth 1 -type d | sort)
[ "$bad" -eq 0 ] || die "$bad of $n packages failed verify"
printf '%s✓ %d packages verified, 0 failures%s\n' "$G" "$n" "$X"

step "4/6  D6 baseline score"
# same seed range as step 2: existing packages are reused (not rebuilt), only scored.
# (--count 0 here used to score nothing and seal an empty baseline.)
$IRIS package batch --count "$COUNT" --out "$STORE" | tee "$REL/baseline_d6.txt"

step "4b/6  Coverage (context tier, D6)"
$IRIS dataset coverage-context "$STORE" | tee "$REL/coverage_context.json" >/dev/null
printf '%s\xe2\x9c\x93 coverage written%s\n' "$G" "$X"

step "5/6  Manifest"
VER="$($IRIS info 2>/dev/null | tr '\n' ' ' || echo unknown)"
SIZE="$(du -sh "$STORE" | cut -f1)"
cat > "$REL/MANIFEST.json" <<JSON
{
  "release": "iris-dataset-${STAMP}",
  "built_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "tier": "context (GRC / D6) — Docker-free",
  "generator_info": "${VER}",
  "store_path": "${STORE}",
  "package_count": ${n},
  "store_size": "${SIZE}",
  "seed_range": "0..$((COUNT-1))",
  "source_date_epoch": ${SOURCE_DATE_EPOCH},
  "reproduce": "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} iris package batch --count ${COUNT} --out ${STORE}",
  "verify": "iris package verify <package-dir>  (0 failures required)"
}
JSON
printf '%s✓ %s/MANIFEST.json%s\n' "$G" "$REL" "$X"

step "6/6  Datasheet"
cat > "$REL/DATASHEET.md" <<MD
# IRIS dataset — context / GRC tier (release ${STAMP})

A synthetic SOC/GRC cyber-range dataset for training and scoring an AI assistant
on **GRC flaw-finding (decision D6)**. Fully reproducible from seeds.

## What this release contains
- **${n} scenarios**, each a self-contained package (${SIZE} total on disk).
- Two planes per scenario:
  - **Visible plane** — everything the model may read: organization, topology,
    identities, services, the GRC **control register** (mapped to NIST 800-53,
    CSF 2.0, ISO 27001 Annex A, CIS v8.1), the **risk register**, policy
    exceptions, the change history, per-episode as-of snapshots and the SOC
    inventory. (SBOM, scanner findings and date-gated CVE intel are added only
    when packages are built with \`--posture\`; this batch build does not.)
  - **Hidden plane** — the ground truth the model is scored against and never
    sees: planted GRC flaws, the D6 reference key, and the composition truth.
- An **integrity guarantee**: every package passes hash + Merkle + no-peek audit
  (0 failures). The no-peek audit proves no hidden identifier leaks into the
  visible plane.

## The task (D6)
Each GRC register has a *recorded* state that may hide a *real* gap. The model
must find those flaws. Fourteen flaw modules are planted: shadow and ghost
assets, paper and understated controls, missing and stale risks, expired
exceptions in use, orphan owners, controls not assessed, misattributed business
processes, gross and understated criticality, and (over time) stale criticality
and stale risk impact after a business change.

## Baseline to beat
A simple rule baseline (reads the visible plane only) scores roughly:
\`\`\`
$(cat "$REL/baseline_d6.txt" | tail -1)
\`\`\`
**Read this carefully:** the rule baseline gets **DC1** (internal inconsistency)
and **DC3** (time) flaws almost always, but **DC2 recall is near zero**: DC2 flaws
need posture and telemetry evidence, which context packages do not carry. Report
DC2 recall on context packages as "not supported by the evidence present", and
judge models on DC1/DC3 here and on DC2 with the train/gold tiers. DC4 flaws are
undetectable by design and excluded from recall; a confident claim on one is
counted as unsupported. \`recall\` credits the right record; \`strict_recall\`
also requires the right flaw type.

## Reproducibility
Same seeds + same SOURCE_DATE_EPOCH → same bytes. Rebuild with:
\`\`\`
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} iris package batch --count ${COUNT} --out ${STORE}
\`\`\`

## Scope and honest limits
- **In scope now (this tier):** GRC registers, SOC configuration/inventory,
  SBOM, date-gated CVEs, and the D6 flaw-finding task. No Docker required.
- **Not in this tier:** live attack telemetry (D1 classification, D2 priority,
  D4 control recommendation from real Wazuh/Suricata alerts). That requires the
  Docker live range to be built and proven on the lab PC, and is released
  separately as the *train* and *gold* tiers.
MD
printf '%s✓ %s/DATASHEET.md%s\n' "$G" "$REL" "$X"

trap - ERR
printf '\n%s════════════════════════════════════════════%s\n' "$G$B" "$X"
printf '%s SEALED: %s%s\n' "$G$B" "$REL" "$X"
printf '%s════════════════════════════════════════════%s\n' "$G$B" "$X"
printf '  %d scenarios · 0 verify failures · datasheet + manifest written\n' "$n"
printf '  open:  %s/DATASHEET.md\n\n' "$REL"
