#!/usr/bin/env bash
# iris-control.sh — IRIS cockpit. Drive the whole generator and SEE what it made.
#
#   ./iris-control.sh            interactive cockpit
#   ./iris-control.sh build 500  non-interactive
#
# GREEN sections run tonight on this laptop (no Docker).
# YELLOW sections need Docker + the lab PC (live attack telemetry).
#
# Override how iris runs:   IRIS="iris" ./iris-control.sh
set -uo pipefail                      # no -e: a failed command must not kill the cockpit

IRIS="${IRIS:-uv run iris}"
STORE="${IRIS_STORE:-/srv/iris/store/context}"
DATASET="${IRIS_DATASET:-/srv/iris/store/dataset}"

G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; D=$'\e[2m'; B=$'\e[1m'; X=$'\e[0m'
ok(){ printf '%s✓%s %s\n' "$G" "$X" "$*"; }
no(){ printf '%s✗%s %s\n' "$R" "$X" "$*"; }
hd(){ printf '\n%s== %s ==%s\n' "$C$B" "$*" "$X"; }
run(){ printf '%s$ %s%s\n' "$D" "$*" "$X"; eval "$@"; }
pp(){ if command -v jq >/dev/null; then jq . ; else python3 -m json.tool ; fi; }
pause(){ read -rp $'\n'"${D}enter to continue${X} "; }

# pick a package dir from the store, sets REPLY_PKG
pick_pkg(){
  local root="${1:-$STORE}" dirs=() i=1
  mapfile -t dirs < <(find "$root" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort)
  if [ "${#dirs[@]}" -eq 0 ]; then no "no packages in $root — generate some first (menu 2)"; return 1; fi
  printf '\n%sPackages in %s%s\n' "$B" "$root" "$X"
  for d in "${dirs[@]}"; do printf '  %2d) %s\n' "$i" "$(basename "$d")"; i=$((i+1)); done
  local n; read -rp "pick # [1]: " n; n="${n:-1}"
  REPLY_PKG="${dirs[$((n-1))]:-}"
  [ -n "$REPLY_PKG" ] && [ -d "$REPLY_PKG" ] || { no "bad choice"; return 1; }
}

# ---------------------------------------------------------------- GREEN tier
check_tree(){ hd "Repository check (make check)"; if make check; then ok "green"; else no "make check failed — read above"; fi; }

gen_spec(){ hd "Sample ONE scenario spec from a master seed"
  read -rp "master seed [42]: " m; m="${m:-42}"
  run "$IRIS gen spec --master $m"; }

gen_grc(){ hd "GRC reality + recorded registers + timeline for one seed"
  read -rp "master seed [42]: " m; m="${m:-42}"
  run "$IRIS gen grc --master $m"; }

gen_compile(){ hd "Compile a spec -> compose.yaml + router.nft + compiled.json"
  read -rp "spec file [examples/golden_v0.spec.yaml]: " f; f="${f:-examples/golden_v0.spec.yaml}"
  read -rp "out dir [/tmp/iris-compile]: " o; o="${o:-/tmp/iris-compile}"
  run "$IRIS gen compile '$f' '$o'" && ok "written to $o"; }

gen_batch(){ hd "Generate + verify N context packages"
  local n="${1:-}"; [ -n "$n" ] || read -rp "how many? [100]: " n; n="${n:-100}"
  run "$IRIS package batch --count $n --out '$STORE'"; }

verify_all(){ hd "Verify every package (hashes, Merkle, no-peek audit)"
  local n=0 bad=0
  while IFS= read -r d; do
    [ -f "$d/manifest.visible.json" ] || continue; n=$((n+1))
    $IRIS package verify "$d" >/dev/null 2>&1 || { bad=$((bad+1)); no "FAILED: $(basename "$d")"; }
  done < <(find "$STORE" -maxdepth 1 -mindepth 1 -type d | sort)
  [ "$bad" -eq 0 ] && ok "$n packages, 0 failures" || no "$bad of $n FAILED"; }

score_d6(){ hd "D6 baseline score (DC2≈0 is expected — that's the model's job)"
  run "$IRIS package batch --count 0 --out '$STORE'"; }

# inspect ONE scenario in plain language
inspect(){
  pick_pkg || return 1; local p="$REPLY_PKG"
  hd "Inside $(basename "$p")"
  python3 - "$p" <<'PY'
import sys, json, pathlib
root = pathlib.Path(sys.argv[1])
def load(rel):
    f = root/rel
    if not f.exists(): return None
    try: return json.loads(f.read_text())
    except Exception: return None
files = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
vis = [f for f in files if "hidden" not in f and "truth" not in f and "/key" not in f]
hid = [f for f in files if f not in vis]
print(f"files: {len(files)}   visible: {len(vis)}   hidden: {len(hid)}\n")
def count(rel):
    f = root/rel
    if not f.exists(): return "-"
    if rel.endswith(".jsonl"): return sum(1 for _ in f.open())
    d = load(rel)
    if isinstance(d, list): return len(d)
    if isinstance(d, dict): return len(d)
    return "?"
print("VISIBLE PLANE (what the model may read):")
for f in vis:
    print(f"  {count(f):>6}  {f}")
print("\nHIDDEN PLANE (ground truth — never shown to the model):")
for f in hid:
    print(f"  {count(f):>6}  {f}")
PY
  echo; read -rp "view one file? type its path (blank to skip): " rel
  [ -n "$rel" ] && [ -f "$p/$rel" ] && { echo; cat "$p/$rel" | ( [ "${rel##*.}" = jsonl ] && head -20 || pp ); }
}

# ---------------------------------------------------------------- dataset
ds_build(){ hd "Build a dataset dir (composes from fragment library)"
  no "needs a fragment library (recorded on the Docker/lab PC). Skipping on laptop is normal."
  read -rp "try anyway? count [0=no]: " n; n="${n:-0}"; [ "$n" -gt 0 ] && run "$IRIS dataset build --start 0 --count $n --out '$DATASET'"; }
ds_splits(){ hd "Preview OOD split assignment"; read -rp "count [50]: " n; n="${n:-50}"; run "$IRIS dataset splits --start 0 --count $n"; }
ds_cov(){ hd "Coverage report (context tier: D6 keys)"; read -rp "dir [$STORE]: " r; r="${r:-$STORE}"; run "$IRIS dataset coverage-context '$r'"; }

# ---------------------------------------------------------------- SOC / seeds / refs
soc_rules(){ hd "Static check of Wazuh rules (configs/soc/local_rules.xml)"; run "$IRIS soc rules"; }
soc_profile(){ hd "What the SOC really collects vs believes, for a seed"
  read -rp "master seed [42]: " m; m="${m:-42}"; run "$IRIS soc profile --master $m"; }
seeds(){ hd "Derive the 10 sub-seeds + group_id"; read -rp "master seed [42]: " m; m="${m:-42}"; run "$IRIS seeds derive $m"; }
refs(){ hd "Pinned references (ATT&CK, NIST, CTID, KEV, EPSS...)"; run "$IRIS refs list"; run "$IRIS refs verify"; }

status(){ hd "Status"; run "$IRIS info"; echo
  if [ -d "$STORE" ]; then
    local n sz; n=$(find "$STORE" -maxdepth 1 -mindepth 1 -type d 2>/dev/null|wc -l|tr -d ' ')
    sz=$(du -sh "$STORE" 2>/dev/null|cut -f1); ok "store: $n packages, $sz  ($STORE)"
  else no "no store yet: $STORE"; fi
  run "df -h /srv/iris 2>/dev/null | tail -1"; }

# ---------------------------------------------------------------- YELLOW tier (lab PC)
lab_note(){ hd "${Y}Docker tier — run on the LAB PC, not here${X}"
  cat <<EOF
  These need Docker + built images. Images are pulled on THIS laptop, saved,
  and copied to the offline lab PC over the LAN. Commands, for reference:

    iris range plan   --master 42        show hosts/images/weaknesses
    iris range build  --master 42        build images (10-20 min first time)
    iris range up     --master 42        deploy, health-gate, teardown
    iris range gate   --count 20         P2 exit gate
    iris range detect-gate --count 10    every expected detection must fire
    iris fragments batch --start 0 --count 20   record the fragment library

  Do these in a separate session once ONE live run passes (workstream 0).
EOF
}

menu(){
  while true; do
    cat <<EOF

${C}${B}IRIS COCKPIT${X}   ${D}store: $STORE${X}

${G}GREEN — tonight, this laptop, no Docker${X}
  1) Check repo (make check)
  2) Generate N context packages
  3) Inspect ONE scenario (see inside, plain language)
  4) Verify all packages (no-peek audit)
  5) D6 baseline score
  6) Generate one spec / GRC / compile   (sub)
  7) SOC rules (static)   8) SOC profile for a seed
  9) Seeds derive        10) References list+verify
 11) Dataset: splits / coverage / build   (sub)
 12) Status (versions, disk, counts)

${Y}YELLOW — lab PC, needs Docker${X}
 13) Show the Docker/live commands

  q) Quit
EOF
    read -rp "> " a
    case "$a" in
      1) check_tree;; 2) gen_batch;; 3) inspect;; 4) verify_all;; 5) score_d6;;
      6) echo " a) spec  b) grc  c) compile"; read -rp " > " s
         case "$s" in a) gen_spec;; b) gen_grc;; c) gen_compile;; esac;;
      7) soc_rules;; 8) soc_profile;; 9) seeds;; 10) refs;;
      11) echo " a) splits  b) coverage  c) build"; read -rp " > " s
          case "$s" in a) ds_splits;; b) ds_cov;; c) ds_build;; esac;;
      12) status;; 13) lab_note;;
      q|Q) exit 0;; *) no "pick a number or q";;
    esac
    pause
  done
}

case "${1:-menu}" in
  menu) menu;; check) check_tree;; build) gen_batch "${2:-100}";;
  verify) verify_all;; score) score_d6;; inspect) inspect;; status) status;;
  *) no "unknown: $1"; echo "try: menu | build N | verify | score | inspect | status";;
esac
