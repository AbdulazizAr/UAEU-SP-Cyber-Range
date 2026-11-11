"""``iris`` command line."""

from __future__ import annotations

import json
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

import click
import yaml
from pydantic import ValidationError

from iris import CONTRACT_SCHEMA_VERSION, GENERATOR_MAJOR, SPEC_VERSION, __version__
from iris.core.hashing import canonical_json, sha256_hex
from iris.core.seeds import SEED_MODULES, SeedSet
from iris.settings import paths, repo_root


def _load_structured(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    return json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)


@click.group()
@click.version_option(__version__, prog_name="iris")
def main() -> None:
    """IRIS cyber range, dataset generator and evaluation harness."""


@main.command()
def info() -> None:
    """Show versions and data locations."""
    p = paths()
    click.echo(f"iris {__version__}  generator_major={GENERATOR_MAJOR}")
    click.echo(f"spec:      {SPEC_VERSION}  contract: {CONTRACT_SCHEMA_VERSION}")
    click.echo(f"repo:      {repo_root()}")
    click.echo(f"IRIS_DATA: {p.data}  ({'exists' if p.data.exists() else 'missing'})")


# ---------------------------------------------------------------- data


@main.group()
def data() -> None:
    """Manage the data directory ($IRIS_DATA)."""


@data.command("init")
def data_init() -> None:
    """Create the standard sub-directories under $IRIS_DATA."""
    p = paths()
    p.ensure()
    click.echo(f"ready: {p.data}")


# ---------------------------------------------------------------- seeds


@main.group()
def seeds() -> None:
    """Seed hierarchy tools."""


@seeds.command("derive")
@click.option("--master", type=int, required=True, help="Master seed (non-negative integer).")
@click.option("--override", "overrides", multiple=True, metavar="MODULE=VALUE", help="Replace one sub-seed.")
def seeds_derive(master: int, overrides: tuple[str, ...]) -> None:
    """Print the 10 sub-seeds and the group_id for a master seed."""
    s = SeedSet.from_master(master)
    for item in overrides:
        module, _, value = item.partition("=")
        if module not in SEED_MODULES or not value.isdigit():
            raise click.BadParameter(
                f"expected MODULE=INT with MODULE in {SEED_MODULES}", param_hint="--override"
            )
        s = s.with_override(module, int(value))
    out = s.to_dict()
    out["group_id"] = s.group_id()
    click.echo(json.dumps(out, indent=2))


# ---------------------------------------------------------------- spec


@main.group()
def spec() -> None:
    """Scenario spec tools."""


@spec.command("validate")
@click.argument(
    "files", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
def spec_validate(files: tuple[Path, ...]) -> None:
    """Validate one or more scenario spec files (YAML or JSON)."""
    from iris.contracts.spec import ScenarioSpec

    failed = 0
    for f in files:
        try:
            s = ScenarioSpec.model_validate(_load_structured(f))
        except ValidationError as exc:
            failed += 1
            click.secho(f"FAIL {f}", fg="red")
            click.echo(str(exc))
            continue
        seed_set = SeedSet.from_dict(s.seeds.model_dump())
        spec_hash = sha256_hex(canonical_json(s.model_dump(mode="json")))[:12]
        click.secho(
            f"OK   {f}  assets={len(s.assets)} services={len(s.services)} episodes={len(s.episodes)} "
            f"group={seed_set.group_id()} spec_hash={spec_hash}",
            fg="green",
        )
    sys.exit(1 if failed else 0)


# ---------------------------------------------------------------- schema


@main.group()
def schema() -> None:
    """Contract schemas."""


@schema.command("export")
@click.option(
    "--out",
    type=click.Path(file_okay=False, path_type=Path),
    default=lambda: str(repo_root() / "schemas" / "generated"),
    show_default="schemas/generated",
)
def schema_export(out: Path) -> None:
    """Write JSON Schemas for the spec, the visible contract and decision records."""
    from iris.contracts.export import export_schemas

    written = export_schemas(out)
    click.echo(f"wrote {len(written)} schemas to {out}")


# ---------------------------------------------------------------- references


@main.group()
def refs() -> None:
    """Pinned external references (ATT&CK, NIST, CTID, ...)."""


@refs.command("list")
def refs_list() -> None:
    from iris.references.registry import load_lock, load_registry

    lock = load_lock()
    for ref_id, s in load_registry().items():
        pinned = lock.get(ref_id, {}).get("sha256", "")[:12] or "-"
        click.echo(f"{ref_id:22} v{s.version:22} {s.fetch:7} pinned={pinned:12} {s.title}")


@refs.command("fetch")
@click.argument("ids", nargs=-1)
@click.option("--repin", is_flag=True, help="Accept new upstream content and update the lock.")
def refs_fetch(ids: tuple[str, ...], repin: bool) -> None:
    """Download references and pin their SHA-256 in configs/references/lock.json."""
    from iris.references.registry import ReferenceError, fetch, load_lock, load_registry, save_lock

    specs = load_registry()
    lock = load_lock()
    selected = ids or tuple(specs)
    failures = 0
    for ref_id in selected:
        if ref_id not in specs:
            raise click.BadParameter(f"unknown reference {ref_id}")
        try:
            entry = fetch(specs[ref_id], lock=None if repin else lock)
        except ReferenceError as exc:
            failures += 1
            click.secho(f"SKIP {ref_id}: {exc}", fg="yellow")
            continue
        lock[ref_id] = entry
        click.secho(f"OK   {ref_id}: {entry['sha256'][:12]} ({entry['size_bytes']} bytes)", fg="green")
    save_lock(lock)
    if failures:
        click.echo(f"{failures} reference(s) not fetched; manual ones must be placed by hand.")


@refs.command("verify")
def refs_verify() -> None:
    """Re-hash every reference (single files and the committed synth bundles) against the lock."""
    from iris.references.registry import load_lock, load_registry, verify
    from iris.synth.refs import verify_bundles

    results = verify(load_registry(), load_lock())
    for r in results:
        colour = {"ok": "green", "mismatch": "red"}.get(r.status, "yellow")
        click.secho(f"{r.status:9} {r.id} {r.detail}", fg=colour)
    bundles = verify_bundles()
    for b in bundles:
        colour = {"ok": "green", "mismatch": "red"}.get(b.status, "yellow")
        click.secho(f"{b.status:9} {b.bundle_id} (bundle) {b.detail}", fg=colour)
    bad = any(r.status == "mismatch" for r in results) or any(b.status == "mismatch" for b in bundles)
    sys.exit(1 if bad else 0)


@refs.command("show")
@click.argument("ref_id")
def refs_show(ref_id: str) -> None:
    """Summarise a pinned reference (ATT&CK, OSCAL catalog or CTID mappings)."""
    from iris.references import attack, mappings, oscal
    from iris.references.registry import load_registry, require

    spec_ = load_registry()[ref_id]
    path = require(ref_id)
    if spec_.kind == "attack_stix":
        cat = attack.load(path)
        wanted = spec_.extra.get("platforms", [])
        scoped = cat.for_platforms(wanted)
        click.echo(f"ATT&CK {cat.version}: {len(cat.tactics)} tactics, {len(cat.techniques)} techniques")
        click.echo(f"in scope for {wanted}: {len(scoped)} techniques")
        click.echo("tactics: " + ", ".join(t.name for t in cat.tactics.values()))
        missing = sorted(set(wanted) - cat.platforms())
        if missing:
            click.secho(f"platform names not in this release: {missing}", fg="yellow")
    elif spec_.kind == "oscal_catalog":
        oc = oscal.load(path)
        click.echo(f"{oc.title} {oc.version}")
        click.echo(f"controls: {len(oc.base_controls())} base, {len(oc.controls)} incl. enhancements")
        click.echo(f"families: {len(oc.families())}, withdrawn: {len(oc.withdrawn)}")
    elif spec_.kind == "ctid_mappings":
        ms = mappings.load(path)
        click.echo(f"{ms.framework}: {len(ms.links)} links, mapped to ATT&CK {ms.attack_version}")
        try:
            cat = attack.load(require("attack-enterprise"))
        except Exception:
            click.secho("attack-enterprise not pinned; skipping version-gap check", fg="yellow")
            return
        gap = mappings.check_against_attack(ms, cat)
        click.echo(f"vs pinned ATT&CK {gap.pinned_attack_version}:")
        click.echo(f"  unknown techniques: {len(gap.unknown)}  retired techniques: {len(gap.retired)}")
    else:
        click.echo(f"{ref_id}: no parser yet for kind {spec_.kind}")


# ---------------------------------------------------------------- generator (P2)


@main.group()
def gen() -> None:
    """Scenario generation: sample specs from seeds, check them, compile to Docker."""


def _overrides(industry: str | None, size: str | None, maturity: str | None, archetype: str | None) -> Any:
    from iris.generator.sampler import SampleOverrides

    return SampleOverrides(industry=industry, size=size, maturity=maturity, archetype=archetype)


@gen.command("spec")
@click.option("--master", type=int, required=True)
@click.option("--industry")
@click.option("--size", type=click.Choice(["S", "M", "L"]))
@click.option("--maturity", type=click.Choice(["low", "medium", "high"]))
@click.option("--archetype")
@click.option("--out", type=click.Path(dir_okay=False, path_type=Path), help="Write the spec as YAML.")
def gen_spec(
    master: int,
    industry: str | None,
    size: str | None,
    maturity: str | None,
    archetype: str | None,
    out: Path | None,
) -> None:
    """Sample one scenario spec from a master seed and summarise it."""
    from iris.generator.invariants import check as invariants
    from iris.generator.sampler import sample_spec

    s = sample_spec(SeedSet.from_master(master), _overrides(industry, size, maturity, archetype))
    o = s.organization
    click.echo(f"{o.name} ({o.industry.value}, {o.size.value}, maturity {o.maturity.value}, {o.timezone})")
    group = SeedSet.from_master(master).group_id()
    click.echo(f"archetype {s.archetype}  zones {[z.name for z in s.zones]}  group {group}")
    for a in s.assets:
        ip = ",".join(att.ip for att in a.attachments) or "(router namespace)"
        flags = ("" if a.monitored else " BLIND") + (" EXPOSED" if a.internet_exposed else "")
        click.echo(
            f"  {a.asset_id:12} {a.hostname:14} {a.role.value:18} {ip:42} crit={a.true_criticality}{flags}"
        )
    click.echo(f"services {len(s.services)}  identities {len(s.identities)}  policy rules {len(s.policy)}")
    click.echo("weaknesses: " + (", ".join(f"{w.module}@{w.asset_id}" for w in s.weaknesses) or "none"))
    click.echo("episodes: " + ", ".join(f"#{e.index} {e.virtual_start.isoformat()}" for e in s.episodes))
    violations = invariants(s)
    for v in violations:
        click.secho(f"  invariant: {v}", fg="red")
    if out:
        out.write_text(yaml.safe_dump(s.model_dump(mode="json"), sort_keys=False), encoding="utf-8")
        click.echo(f"wrote {out}")
    sys.exit(1 if violations else 0)


@gen.command("batch")
@click.option("--start", type=int, default=0, show_default=True)
@click.option("--count", type=int, default=1000, show_default=True)
def gen_batch(start: int, count: int) -> None:
    """Sample many specs; report validity, invariant violations and factor coverage."""
    from collections import Counter

    from iris.generator.invariants import check as invariants
    from iris.generator.invariants import container_count
    from iris.generator.sampler import sample_spec

    cov: dict[str, Counter[str]] = {k: Counter() for k in ("archetype", "size", "maturity", "industry")}
    failures, containers, weaknesses = 0, Counter[str](), Counter[int]()
    for m in range(start, start + count):
        try:
            s = sample_spec(SeedSet.from_master(m))
        except ValidationError as exc:
            failures += 1
            click.secho(f"seed {m}: invalid spec: {str(exc)[:300]}", fg="red")
            continue
        violations = invariants(s)
        if violations:
            failures += 1
            click.secho(f"seed {m}: {violations}", fg="red")
        cov["archetype"][s.archetype] += 1
        cov["size"][s.organization.size.value] += 1
        cov["maturity"][s.organization.maturity.value] += 1
        cov["industry"][s.organization.industry.value] += 1
        containers[s.organization.size.value] = max(containers[s.organization.size.value], container_count(s))
        weaknesses[len(s.weaknesses)] += 1
    click.echo(f"{count} specs, {failures} failing")
    for key, counter in cov.items():
        click.echo(f"  {key:10} " + "  ".join(f"{k}={v}" for k, v in sorted(counter.items())))
    click.echo("  max containers by size: " + "  ".join(f"{k}={v}" for k, v in sorted(containers.items())))
    click.echo("  weaknesses per scenario: " + "  ".join(f"{k}:{v}" for k, v in sorted(weaknesses.items())))
    sys.exit(1 if failures else 0)


@gen.command("grc")
@click.option("--master", type=int, required=True)
@click.option("--maturity", type=click.Choice(["low", "medium", "high"]))
@click.option(
    "--out", type=click.Path(file_okay=False, path_type=Path), help="Write visible/ and hidden/ JSON."
)
def gen_grc(master: int, maturity: str | None, out: Path | None) -> None:
    """GRC reality, recorded registers (noise, flaws, diff audit), timeline and as-of snapshots."""
    from collections import Counter

    from iris.generator.grc.recorded import build_grc
    from iris.generator.grc.timeline import build_timeline
    from iris.generator.sampler import sample_spec

    spec = sample_spec(SeedSet.from_master(master), _overrides(None, None, maturity, None))
    b = build_grc(spec)
    s = b.style
    click.echo(f"{spec.organization.name}: maturity {spec.organization.maturity.value}")
    click.echo(f"style: risk {s.risk_scale}, criticality {s.criticality_scale}")
    click.echo(f"       vocabulary {s.vocabulary}, review {s.cadence}")
    states = Counter(c.state for c in b.reality.controls.values())
    click.echo(f"controls (reality): {dict(sorted(states.items()))}")
    for r in b.reality.risks.values():
        click.echo(f"  {r.risk_id:12} L{r.likelihood} x I{r.impact} -> residual {r.residual:5}  {r.scenario}")
    click.echo(f"exceptions: {len(b.reality.exceptions)}  noise changes: {b.audit.noise_changes}")
    click.echo(f"flaws: {len(b.ledger)}")
    for f in b.ledger:
        click.echo(f"  {f.flaw_id} {f.module:28} {f.level} {f.detectability}  {f.object_ref}")
    colour = "green" if b.audit.ok else "red"
    click.secho(
        f"diff audit: {'OK' if b.audit.ok else 'FAILED'} ({b.audit.differences} differences explained)",
        fg=colour,
    )
    t = build_timeline(spec, b)
    click.echo(f"timeline: {len(t.events)} reality events, {len(t.changes)} recorded changes")
    for e in t.events:
        click.echo(f"  {e.event_id} {e.effective_at:%Y-%m-%d} {e.kind:22} {e.entity_ref}")
    for i in t.items:
        state = f"fixed {i.resolved_at:%Y-%m-%d} by {i.resolved_by}" if i.resolved_at else "still open at end"
        click.echo(f"  {i.item_id} {i.change_type:22} {i.entity_type}:{i.entity_id}  {state}")
    held = sum(1 for r in t.reviews if r.held)
    click.echo(f"reviews: {held} held / {len(t.reviews)} scheduled ({s.cadence})")
    for eid, at in t.episodes:
        active = t.active_flaws(at)
        timeline_n = sum(1 for f in active if f.origin == "timeline")
        click.echo(
            f"  {eid} as of {at:%Y-%m-%d %H:%M}: {len(active)} active flaws ({timeline_n} from timeline)"
        )
    if out:
        hidden = b.hidden() | t.hidden()  # the timeline ledger includes the baseline flaws
        _write_planes(out, {"visible": b.visible() | t.visible(), "hidden": hidden})
    sys.exit(0 if b.audit.ok else 1)


def _write_planes(out: Path, planes: dict[str, dict[str, Any]]) -> None:
    from iris.packager.build import json_default

    for plane, files in planes.items():
        for rel, content in files.items():
            path = out / plane / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            if rel.endswith(".jsonl"):
                text = "".join(json.dumps(row, default=json_default) + "\n" for row in content)
            else:
                text = json.dumps(content, indent=2, default=json_default) + "\n"
            path.write_text(text, encoding="utf-8")
    click.echo(f"wrote {', '.join(f'{out}/{p}' for p in planes)}")


@gen.command("compile")
@click.argument("spec_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", type=click.Path(file_okay=False, path_type=Path), required=True)
def gen_compile(spec_file: Path, out: Path) -> None:
    """Compile a spec into compose.yaml, router.nft and compiled.json."""
    from iris.contracts.spec import ScenarioSpec
    from iris.generator.compiler import compile_spec

    compiled = compile_spec(ScenarioSpec.model_validate(_load_structured(spec_file)))
    compiled.write(out)
    m = compiled.meta
    click.echo(f"{m['project']}: {m['container_count']} containers, ~{m['mem_estimate_mib']} MiB")
    click.echo(f"images to build or pull: {len(m['images'])}")
    click.echo(f"wrote {out}/compose.yaml, router.nft, compiled.json")


# ---------------------------------------------------------------- posture


@main.group()
def posture() -> None:
    """SBOM, Trivy scans (offline, cached per image) and date-gated vulnerability intel."""


@posture.command("db")
def posture_db() -> None:
    """Download the Trivy DB once (network) and pack it as the trivy-db reference."""
    from iris.generator.posture.scan import TRIVY_IMAGE, make_db_snapshot

    target = make_db_snapshot()
    click.echo(f"{TRIVY_IMAGE}: DB snapshot written to {target}")
    click.echo("pin it with: uv run iris refs fetch trivy-db   (add --repin to replace an older snapshot)")


def _db() -> Any:
    from iris.generator.posture.scan import unpack_db
    from iris.references.registry import load_lock, require

    tarball = require("trivy-db")
    return unpack_db(tarball, load_lock()["trivy-db"]["sha256"])


@posture.command("scan")
@click.option("--master", type=int, multiple=True, help="Scan every image a sampled enterprise uses.")
@click.option("--image", "images", multiple=True, help="Scan these image references.")
@click.option("--force", is_flag=True, help="Rescan even when the cache matches digest and DB.")
def posture_scan(master: tuple[int, ...], images: tuple[str, ...], force: bool) -> None:
    """Scan built images with Trivy (no network, no Docker socket) into the posture cache."""
    from iris.generator.compiler import asset_images
    from iris.generator.posture.scan import scan_image
    from iris.generator.sampler import sample_spec

    wanted = set(images)
    for m in master:
        spec = sample_spec(SeedSet.from_master(m))
        wanted |= {
            img for aid, img in asset_images(spec).items() if not aid.startswith(("AST-RTR", "AST-IDS"))
        }
    if not wanted:
        raise click.UsageError("give --master or --image")
    db = _db()
    failed = 0
    for img in sorted(wanted):
        try:
            path = scan_image(img, db, force=force)
            summary = json.loads(path.read_text(encoding="utf-8"))["summary"]
            click.echo(f"ok    {img}: {summary['packages']} packages, {summary['cves']} CVEs")
        except Exception as exc:  # report every image, then fail at the end
            failed += 1
            click.secho(f"FAIL  {img}: {exc}", fg="red")
    sys.exit(1 if failed else 0)


@posture.command("show")
@click.argument("image")
def posture_show(image: str) -> None:
    """Summarise one cached scan."""
    from collections import Counter

    from iris.generator.posture.trivy import load_cached

    rep = load_cached(image)
    if rep is None:
        raise click.ClickException(f"no cached scan for {image}")
    sev = Counter(v.severity for v in rep.vulns)
    click.echo(f"{image}  {rep.os_family} {rep.os_name}  id {rep.image_id}")
    click.echo(f"packages {len(rep.packages)}  CVEs {len({v.cve_id for v in rep.vulns})}  {dict(sev)}")
    click.echo(f"scanner {rep.meta.get('scanner')}  db {rep.meta.get('db')}")


@posture.command("build")
@click.option("--master", type=int, required=True)
@click.option("--out", type=click.Path(file_okay=False, path_type=Path), help="Write visible/ and hidden/.")
def posture_build(master: int, out: Path | None) -> None:
    """Enterprise GRC + timeline + posture for one seed, with merged as-of snapshots."""
    from iris.generator.compiler import asset_images
    from iris.generator.grc.recorded import build_grc
    from iris.generator.grc.timeline import build_timeline
    from iris.generator.posture.build import MissingScans, build_posture
    from iris.generator.posture.scan import TRIVY_VERSION
    from iris.generator.posture.trivy import load_cached
    from iris.generator.sampler import sample_spec
    from iris.references.intel import Intel, load_intel
    from iris.references.registry import ReferenceError

    seeds = SeedSet.from_master(master)
    spec = sample_spec(seeds)
    grc = build_grc(spec, seeds)
    tl = build_timeline(spec, grc, seeds)
    reports = {img: r for img in set(asset_images(spec).values()) if (r := load_cached(img)) is not None}
    db_meta: dict[str, Any] = next((r.meta.get("db", {}) for r in reports.values()), {})
    try:
        p = build_posture(spec, grc, reports, Intel(kev={}), [], seeds)  # cheap check: scans present?
        p = build_posture(spec, grc, reports, load_intel(), tl.episodes, seeds, TRIVY_VERSION, db_meta)
    except MissingScans as exc:
        raise click.ClickException(f"{exc}\n  e.g. uv run iris posture scan --master {master}") from exc
    except ReferenceError as exc:
        raise click.ClickException(f"{exc}\n  vulnerability intel must be pinned first: make refs") from exc
    sc = p.reality["scanner"]
    click.echo(f"{spec.organization.name}: scanning {sc['control_state']} (every {sc['cadence_days']} days)")
    click.echo(f"  scanned {len(sc['scanned_assets'])}, unscanned {len(sc['unscanned_assets'])}")
    click.echo(f"  findings {len(p.findings)}, enrichment rows {len(p.enrichment)}, SBOMs {len(p.sboms)}")
    click.echo(f"  hidden by date gate: {p.reality['hidden_by_date_gate']}")
    if out:
        visible = grc.visible() | tl.visible() | p.visible()
        for eid, _ in tl.episodes:
            visible[f"snapshots/asof/{eid}.json"] |= p.asof(eid)
        hidden = grc.hidden() | tl.hidden() | p.hidden() | {"truth/posture_meta.json": p.meta}
        _write_planes(out, {"visible": visible, "hidden": hidden})


# ---------------------------------------------------------------- packages, baselines, evaluation (P6)


def _packages_dir(out: Path | None) -> Path:
    return out or paths().store / "context"


def _posture_inputs(spec: Any) -> tuple[Any, Any, str, dict[str, Any]]:
    from iris.generator.compiler import asset_images
    from iris.generator.posture.scan import TRIVY_VERSION
    from iris.generator.posture.trivy import load_cached
    from iris.references.intel import load_intel

    reports = {img: r for img in set(asset_images(spec).values()) if (r := load_cached(img)) is not None}
    db_meta: dict[str, Any] = next((r.meta.get("db", {}) for r in reports.values()), {})
    return reports, load_intel(), TRIVY_VERSION, db_meta


@main.group()
def package() -> None:
    """Build and verify scenario packages (visible + hidden planes)."""


@package.command("build")
@click.option("--master", type=int, required=True)
@click.option("--maturity", type=click.Choice(["low", "medium", "high"]))
@click.option("--posture", "with_posture", is_flag=True, help="Include posture (needs cached scans + intel).")
@click.option(
    "--out", type=click.Path(file_okay=False, path_type=Path), help="Default: $IRIS_DATA/store/context"
)
def package_build(master: int, maturity: str | None, with_posture: bool, out: Path | None) -> None:
    """Build one context package and verify it."""
    from iris.generator.sampler import sample_spec
    from iris.packager.build import assemble, write_package
    from iris.packager.verify import verify_package

    seeds = SeedSet.from_master(master)
    ov = _overrides(None, None, maturity, None)
    extra: dict[str, Any] = {}
    if with_posture:
        reports, intel, version, db_meta = _posture_inputs(sample_spec(seeds, ov))
        extra = {"reports": reports, "intel": intel, "scanner_version": version, "db_meta": db_meta}
    try:
        res = write_package(assemble(seeds, ov, **extra), _packages_dir(out))
    except FileExistsError as exc:
        raise click.ClickException(str(exc)) from exc
    rep = verify_package(res.root)
    click.echo(f"{res.package_id}  {res.root}")
    click.echo(
        f"  visible files {res.visible_files}, hidden files {res.hidden_files}, merkle {res.merkle_root[:16]}"
    )
    _verdict(rep)


def _verdict(rep: Any) -> None:
    if rep.ok:
        click.secho(f"  verify OK ({rep.checked_files} visible files checked)", fg="green")
        return
    for p in rep.problems[:20]:
        click.secho(f"  {p}", fg="red")
    click.secho(f"  verify FAILED ({len(rep.problems)} problems)", fg="red")
    sys.exit(1)


@package.command("verify")
@click.argument("root", type=click.Path(exists=True, file_okay=False, path_type=Path))
def package_verify(root: Path) -> None:
    """Integrity (hashes, Merkle), contract validity and the no-peek audit."""
    from iris.packager.verify import verify_package

    click.echo(str(root))
    _verdict(verify_package(root))


@package.command("batch")
@click.option("--start", type=int, default=0, show_default=True)
@click.option("--count", type=int, default=100, show_default=True)
@click.option(
    "--out", type=click.Path(file_okay=False, path_type=Path), help="Default: $IRIS_DATA/store/context"
)
def package_batch(start: int, count: int, out: Path | None) -> None:
    """Build, verify and baseline-score many context packages (skips ones that exist)."""
    import time as _time

    from iris.engine.baselines.d6_rules import decide
    from iris.evaluator.d6 import D6Score, score_package
    from iris.packager.build import assemble, write_package
    from iris.packager.verify import verify_package

    base = _packages_dir(out)
    total, failed, built = D6Score(), 0, 0
    t0 = _time.perf_counter()
    for m in range(start, start + count):
        a = assemble(SeedSet.from_master(m))
        root = base / f"scenario-{a.scenario_id}"
        if not root.exists():
            write_package(a, base)
            built += 1
        if not verify_package(root).ok:
            failed += 1
            click.secho(f"verify FAILED: {root}", fg="red")
        total.merge(score_package(root, decide(root / "visible")))
    secs = _time.perf_counter() - t0
    click.echo(f"{count} packages in {base} ({built} new) in {secs:.1f}s; verify failures: {failed}")
    click.echo("D6 rule baseline: " + json.dumps(total.summary()))
    sys.exit(1 if failed else 0)


@main.group()
def baseline() -> None:
    """Baselines that read the visible plane only."""


@baseline.command("d6")
@click.argument("root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--out", type=click.Path(dir_okay=False, path_type=Path), help="decisions.jsonl")
def baseline_d6(root: Path, out: Path | None) -> None:
    """Rule baseline for D6 (GRC flaw finding) on one package."""
    from iris.engine.baselines.d6_rules import decide

    decisions = decide(root / "visible")
    lines = [d.model_dump_json() for d in decisions]
    if out:
        out.write_text("".join(x + "\n" for x in lines), encoding="utf-8")
        click.echo(f"{len(lines)} decisions -> {out}")
    else:
        for d in decisions:
            assert d.payload is not None and d.payload.type == "D6"
            click.echo(f"{d.episode_id}  {d.confidence:.2f}  {d.payload.flaw_type:28} {d.payload.record_ref}")


@main.group("eval")
def eval_() -> None:
    """Score Engine decisions against a package's hidden reference key."""


def _load_decisions(path: Path, root: Path) -> list[Any]:
    """Parse a decisions.jsonl file. A malformed line is reported with its line number
    (instead of a traceback); duplicate decision IDs and decisions for another scenario
    are reported as warnings so a mixed-up file is noticed before its score is trusted."""
    from iris.contracts.decisions import DecisionRecord

    recs: list[Any] = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            recs.append(DecisionRecord.model_validate_json(line))
        except ValidationError as exc:
            first = str(exc).splitlines()
            raise click.ClickException(f"{path}:{n}: invalid decision record: {' '.join(first[:3])}") from exc
    dupes = sorted(k for k, v in Counter(r.decision_id for r in recs).items() if v > 1)
    if dupes:
        click.secho(f"warning: {len(dupes)} duplicate decision_id(s), e.g. {dupes[0]}", fg="yellow", err=True)
    manifest = root / "visible" / "manifest.visible.json"
    if manifest.exists():
        scn = json.loads(manifest.read_text(encoding="utf-8")).get("scenario_id")
        other = sum(1 for r in recs if r.scenario_id != scn)
        if other:
            click.secho(
                f"warning: {other} decision(s) are for a scenario other than {scn}", fg="yellow", err=True
            )
    return recs


_ROOT_ARG = click.argument("root", type=click.Path(exists=True, file_okay=False, path_type=Path))
_DECISIONS_OPT = click.option(
    "--decisions", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True
)


@eval_.command("d6")
@_ROOT_ARG
@_DECISIONS_OPT
def eval_d6(root: Path, decisions: Path) -> None:
    """D6 recall by detectability class, precision, type accuracy, false alarms, Brier."""
    from iris.evaluator.d6 import score_package

    click.echo(json.dumps(score_package(root, _load_decisions(decisions, root)).summary(), indent=2))


def _eval_types(root: Path, decisions: Path, types: tuple[str, ...]) -> None:
    from iris.evaluator.decisions import score_decisions

    summary = score_decisions(root, _load_decisions(decisions, root)).summary(types)
    click.echo(json.dumps(summary if len(types) > 1 else summary[types[0]], indent=2))


@eval_.command("d1")
@_ROOT_ARG
@_DECISIONS_OPT
def eval_d1(root: Path, decisions: Path) -> None:
    """D1 classification: accuracy, attack recall, benign FPR, macro-F1, harmful, Brier."""
    _eval_types(root, decisions, ("D1",))


@eval_.command("d2")
@_ROOT_ARG
@_DECISIONS_OPT
def eval_d2(root: Path, decisions: Path) -> None:
    """D2 priority: exact and within-one accuracy, under/over-prioritised, harmful."""
    _eval_types(root, decisions, ("D2",))


@eval_.command("d4")
@_ROOT_ARG
@_DECISIONS_OPT
def eval_d4(root: Path, decisions: Path) -> None:
    """D4 control recommendation: control recall/precision, action accuracy, hit@1, harmful."""
    _eval_types(root, decisions, ("D4",))


@eval_.command("all")
@_ROOT_ARG
@_DECISIONS_OPT
def eval_all(root: Path, decisions: Path) -> None:
    """Every scored type (D1, D2, D4, D6) in one report."""
    from iris.evaluator.d6 import score_package
    from iris.evaluator.decisions import score_decisions

    recs = _load_decisions(decisions, root)
    out = score_decisions(root, recs).summary()
    out["D6"] = score_package(root, recs).summary()
    click.echo(json.dumps(out, indent=2))


# ---------------------------------------------------------------- live range (P2)


@main.group("range")
def range_() -> None:
    """Live range: build images, deploy, health gate, teardown (Docker)."""


def _print_summary(sm: Any) -> None:
    if sm.conflict:
        click.secho(f"seed {sm.master}  SKIPPED: subnet conflict on this machine", fg="yellow")
        for c in sm.conflict[:4]:
            click.echo(f"  {c}")
        return
    colour = "green" if sm.healthy and not sm.leftovers else "red"
    click.secho(f"seed {sm.master}  {sm.project}  {sm.state}  healthy={sm.healthy}", fg=colour)
    t = sm.timings
    click.echo(
        f"  build {t.get('build_s', 0)} s, up {t.get('compose_up_s', '-')} s,"
        f" sensor {t.get('sensor_start_s', '-')} s,"
        f" health {t.get('health_s', '-')} s, teardown {t.get('teardown_s', '-')} s;"
        f" {sm.containers} containers, {sm.mem_total_mib} MiB"
    )
    for name in sm.failed_checks:
        click.secho(f"  failed: {name}: {sm.failed_details.get(name, '')}", fg="red")
    if sm.error:
        click.secho(f"  error: {sm.error}", fg="red")
    if sm.leftovers:
        click.secho(f"  leftovers: {sm.leftovers}", fg="red")
    click.echo(f"  details: {sm.run_dir}/health.json")


@range_.command("plan")
@click.option("--master", type=int, required=True)
def range_plan(master: int) -> None:
    """Show the live enterprise for a seed: hosts, images to build, weaknesses."""
    from iris.generator.compiler import compile_spec
    from iris.generator.sampler import SampleOverrides, sample_spec

    spec = sample_spec(SeedSet.from_master(master), SampleOverrides(live=True))
    c = compile_spec(spec)
    click.echo(
        f"{spec.organization.name} ({c.project}), {c.meta['container_count']} containers,"
        f" ~{c.meta['mem_estimate_mib']} MiB"
    )
    for a in spec.assets:
        svcs = ", ".join(
            f"{s.recipe} {s.version}:{s.port}" for s in spec.services if s.asset_id == a.asset_id
        )
        ip = a.attachments[0].ip if a.attachments else "(router ns)"
        mon = "agent" if a.monitored and a.role.value not in ("ids_sensor", "siem") else "-"
        click.echo(f"  {a.hostname:14} {a.role.value:18} {ip:15} {mon:8}  {svcs}")
    for w in spec.weaknesses:
        click.echo(f"  weakness {w.module:22} on {w.asset_id}")
    click.echo("images:")
    for img in c.meta["images"]:
        click.echo(f"  {img}")


@range_.command("build")
@click.option("--master", type=int, multiple=True, required=True)
@click.option("--force", is_flag=True)
def range_build(master: tuple[int, ...], force: bool) -> None:
    """Build every image the live enterprises of these seeds need."""
    from iris.generator.compiler import compile_spec
    from iris.generator.sampler import SampleOverrides, sample_spec
    from iris.live.images import ensure_images
    from iris.spikes.common import require_docker

    require_docker()
    for m in master:
        meta = compile_spec(sample_spec(SeedSet.from_master(m), SampleOverrides(live=True))).meta
        for image, secs in ensure_images(meta, force=force).items():
            click.echo(f"  {image}: {'reused' if secs == 0.0 else secs}")


@range_.command("up")
@click.option("--master", type=int, required=True)
@click.option("--keep", is_flag=True, help="Leave the range running (iris range down to remove).")
@click.option("--no-build", is_flag=True)
@click.option("--light", is_flag=True, help="Production gate: skip the slow acceptance-only checks.")
def range_up(master: int, keep: bool, no_build: bool, light: bool) -> None:
    """Deploy one live enterprise, run the health gate, tear down (unless --keep)."""
    from iris.live.gate import run_once
    from iris.spikes.common import SpikeError

    try:
        sm = run_once(master, keep=keep, build=not no_build, light=light)
    except SpikeError as exc:
        raise click.ClickException(str(exc)) from exc
    _print_summary(sm)
    sys.exit(0 if sm.healthy and not sm.leftovers else 1)


@range_.command("down")
@click.argument("project", required=False)
@click.option("--all", "all_", is_flag=True, help="Every iris project on this machine.")
def range_down(project: str | None, all_: bool) -> None:
    """Remove a kept range (all containers, networks and volumes with its label)."""
    from iris.live.deploy import down_project, running_projects

    if all_:
        targets = sorted(running_projects())
        if not targets:
            click.echo("no iris ranges on this machine")
            return
    elif project:
        targets = [project]
    else:
        raise click.UsageError("give a PROJECT or --all")
    for p in targets:
        left = down_project(p)
        click.echo(f"{p}: {'clean' if not left else f'left {left}'}")


@range_.command("status")
def range_status() -> None:
    """Iris projects with containers on this machine."""
    from iris.live.deploy import running_projects

    projects = running_projects()
    if not projects:
        click.echo("no iris ranges on this machine")
    for p, names in sorted(projects.items()):
        click.echo(f"{p}: {len(names)} containers")


@range_.command("record")
@click.option("--master", type=int, required=True)
@click.option("--episodes", type=int, default=None, help="How many episodes (default: all in the spec).")
@click.option("--keep", is_flag=True)
@click.option("--no-build", is_flag=True)
def range_record(master: int, episodes: int | None, keep: bool, no_build: bool) -> None:
    """Deploy, record each episode's telemetry, verify SOC detections, tear down."""
    from iris.live.gate import record_once
    from iris.spikes.common import SpikeError

    try:
        sm = record_once(master, episodes=episodes, keep=keep, build=not no_build)
    except SpikeError as exc:
        raise click.ClickException(str(exc)) from exc
    if sm.conflict:
        click.secho(f"seed {master}: SKIPPED (subnet conflict)", fg="yellow")
        return
    colour = "green" if sm.detections_ok else "red"
    click.secho(
        f"seed {master}  {sm.project}  healthy={sm.healthy}  detections_ok={sm.detections_ok}", fg=colour
    )
    for e in sm.episodes:
        line = (
            f"  {e['episode_id']}  alerts {e['counts'].get('alerts_visible')},"
            f" eve {e['counts'].get('eve_visible')},"
            f" detect {len(e['expected']) - len(e['missed'])}/{len(e['expected'])}"
        )
        click.secho(
            line + (f"  MISSED {e['missed']}" if e["missed"] else ""), fg="red" if e["missed"] else None
        )
    if sm.error:
        click.secho(f"  error: {sm.error}", fg="red")
    click.echo(f"  episodes: {sm.run_dir}/episodes")
    sys.exit(0 if sm.detections_ok else 1)


@range_.command("detect-gate")
@click.option("--start", type=int, default=0, show_default=True)
@click.option("--count", type=int, default=10, show_default=True)
def range_detect_gate(start: int, count: int) -> None:
    """P3 exit gate: COUNT seeds record episodes whose expected detections all fire."""
    from iris.live.gate import record_once
    from iris.spikes.common import SpikeError

    ran: list[Any] = []
    skipped: list[int] = []
    m = start
    while len(ran) < count and m < start + count * 3:
        try:
            sm = record_once(m, build=True)
        except SpikeError as exc:
            raise click.ClickException(str(exc)) from exc
        if sm.conflict:
            skipped.append(m)
            click.secho(f"seed {m}: SKIPPED (subnet conflict)", fg="yellow")
        else:
            ran.append(sm)
            colour = "green" if sm.detections_ok else "red"
            total_missed = [r for e in sm.episodes for r in e["missed"]]
            click.secho(
                f"seed {m}  detections_ok={sm.detections_ok}  episodes {len(sm.episodes)}"
                + (f"  missed {total_missed}" if total_missed else ""),
                fg=colour,
            )
        m += 1
    ok = [r for r in ran if r.detections_ok]
    click.echo(
        f"\ndetection gate: {len(ok)}/{len(ran)} seeds with all expected detections (skipped {skipped})"
    )
    out = paths().runs / "live" / f"detect-gate-{start}-{m - 1}.json"
    out.write_text(json.dumps([r.__dict__ for r in ran], indent=2, default=str) + "\n")
    click.echo(f"summary: {out}")
    sys.exit(0 if ran and len(ok) == len(ran) == count else 1)


@range_.command("gate")
@click.option("--start", type=int, default=0, show_default=True)
@click.option("--count", type=int, default=20, show_default=True, help="Seeds that must actually run.")
def range_gate(start: int, count: int) -> None:
    """P2 exit gate: COUNT seeds must deploy, pass health and tear down cleanly.

    Seeds whose subnets collide with networks already on this machine are skipped and
    replaced by the next seed (a lane problem, not a range failure).
    """
    from iris.live.gate import run_once
    from iris.spikes.common import SpikeError

    results: list[Any] = []
    skipped: list[Any] = []
    m = start
    while len(results) < count and m < start + count * 3:
        try:
            sm = run_once(m, build=True)
        except SpikeError as exc:
            raise click.ClickException(str(exc)) from exc
        _print_summary(sm)
        (skipped if sm.conflict else results).append(sm)
        m += 1
    ok = [r for r in results if r.healthy and not r.leftovers]
    click.echo(
        f"\nexit gate: {len(ok)}/{len(results)} healthy with clean teardown"
        f" (seeds {start}..{m - 1}; skipped for subnet conflicts: {[r.master for r in skipped]})"
    )
    out = paths().runs / "live" / f"gate-{start}-{m - 1}.json"
    out.write_text(json.dumps([r.__dict__ for r in results + skipped], indent=2, default=str) + "\n")
    click.echo(f"summary: {out}")
    sys.exit(0 if results and len(ok) == len(results) == count else 1)


# ---------------------------------------------------------------- SOC (P3)


@main.group()
def soc() -> None:
    """SOC configuration: detection rules, rule tests, SOC profiles."""


@soc.command("rules")
def soc_rules() -> None:
    """Static check of configs/soc/local_rules.xml (IDs, parents, ATT&CK tags)."""
    from iris.live.logtest import parse_rules, rules_path, rules_report
    from iris.references.registry import ReferenceError, require

    attack_ids: set[str] | None = None
    try:
        from iris.references.attack import load

        cat = load(require("attack-enterprise"))
        attack_ids = set(cat.techniques) - cat.retired
        click.echo(f"ATT&CK {cat.version}: {len(attack_ids)} current techniques")
    except ReferenceError as exc:
        click.secho(f"ATT&CK not pinned, tags checked for format only ({exc})", fg="yellow")
    rules = parse_rules(rules_path().read_text(encoding="utf-8"))
    problems = rules_report(attack_ids)
    tagged = sum(1 for r in rules if r["mitre"])
    click.echo(f"{len(rules)} rules, {tagged} with ATT&CK tags")
    for p in problems:
        click.secho(f"  {p}", fg="red")
    click.secho(
        "rules OK" if not problems else f"{len(problems)} problem(s)", fg="green" if not problems else "red"
    )
    sys.exit(0 if not problems else 1)


@soc.command("logtest")
def soc_logtest() -> None:
    """Run the rule test suite in a throwaway Wazuh manager (Docker, ~1 min)."""
    from iris.live.logtest import run_logtest
    from iris.spikes.common import require_docker

    require_docker()
    results = run_logtest()
    for r in results:
        colour = "green" if r.ok else "red"
        click.secho(f"  {'pass' if r.ok else 'FAIL'}  {r.name:36} want {r.expected}  got {r.got}", fg=colour)
    failed = [r for r in results if not r.ok]
    if failed:
        click.echo(f"--- wazuh-logtest output for the first failure ({failed[0].name}) ---")
        click.echo(failed[0].raw or "(empty)")
    click.echo(f"{len(results) - len(failed)}/{len(results)} rule tests passed")
    sys.exit(0 if not failed else 1)


@soc.command("profile")
@click.option("--master", type=int, required=True)
@click.option("--live", is_flag=True, help="Use the live build matrix.")
def soc_profile(master: int, live: bool) -> None:
    """What the SOC really collects for a seed, what it believes, and the gaps."""
    from iris.generator.grc.recorded import build_grc
    from iris.generator.sampler import SampleOverrides, sample_spec
    from iris.generator.soc import belief_gaps, build_soc

    seeds = SeedSet.from_master(master)
    spec = sample_spec(seeds, SampleOverrides(live=live))
    grc = build_grc(spec, seeds)
    prof = build_soc(spec, grc.reality, seeds)
    recorded = {c.control_id: c.implementation_state for c in grc.controls}
    host = {a.asset_id: a.hostname for a in spec.assets}
    kept = "kept" if prof.archives_retained else "not kept"
    click.echo(
        f"{spec.organization.name}: maturity {spec.organization.maturity.value},"
        f" alerts kept {prof.alert_retention_days} d, archives {kept}"
    )
    for aid, real in prof.sources.items():
        missing = [s for s in prof.believed[aid] if s not in real]
        fim, sca = ("on" if prof.fim[aid] else "off"), ("on" if prof.sca[aid] else "off")
        extra = f"  MISSING {missing}" if missing else ""
        click.echo(f"  {host[aid]:12} sources {','.join(real):40} fim={fim} sca={sca}{extra}")
    for g in belief_gaps(prof, recorded):
        click.echo(f"  gap {g.gap_id} {g.kind:22} {host[g.asset_id]:12} {g.detail}")


# ---------------------------------------------------------------- fragments (P4)


@main.group()
def fragments() -> None:
    """Record and inspect activity fragments (record-and-compose)."""


def _record_one(master: int, no_build: bool, on_phase: Callable[[str], None] | None = None) -> list[Any]:
    """Deploy one enterprise, record a fragment per activity, always tear down. Teardown is
    robust to a failed or interrupted health check (never masks the real error). ``on_phase``
    is called with a short label as each stage begins, for live status display."""
    from iris.fragments.record import record_fragments
    from iris.generator.sampler import SampleOverrides, sample_spec
    from iris.live import deploy as d
    from iris.live.health import Target

    def phase(label: str) -> None:
        if on_phase is not None:
            on_phase(label)

    seeds = SeedSet.from_master(master)
    spec = sample_spec(seeds, SampleOverrides(live=True))
    run = d.new_run(spec)
    frags: list[Any] = []
    try:
        if not no_build:
            phase("building images")
            d.build(run)
        phase("deploying containers")
        d.deploy(run)
        phase("health gate")
        if d.check(run, light=True):
            phase("recording activity")
            frags = record_fragments(Target(spec, run.project, run.compiled.meta), seeds.group_id())
    finally:
        phase("tearing down")
        d.teardown(run)
        d.save(run)
    return frags


@fragments.command("record")
@click.option("--master", type=int, required=True)
@click.option("--no-build", is_flag=True)
def fragments_record(master: int, no_build: bool) -> None:
    """Deploy one enterprise, record a fragment per activity, tear down."""
    from iris.live import deploy as d
    from iris.spikes.common import SpikeError, require_docker

    require_docker()
    if sorted(d.running_projects()):
        raise click.ClickException("other range projects are present (iris range down --all)")
    group = SeedSet.from_master(master).group_id()
    try:
        frags = _record_one(master, no_build)
    except SpikeError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"recorded {len(frags)} fragments into group {group}")
    for f in frags:
        click.echo(
            f"  {f.fragment_id}  {f.truth.label:9} {f.truth.family:18}"
            f" {len(f.records)} records, {len(f.tokens)} tokens"
        )
    sys.exit(0 if frags else 1)


@fragments.command("batch")
@click.option("--start", type=int, default=0, show_default=True)
@click.option("--count", type=int, default=6, show_default=True)
@click.option("--no-build", is_flag=True, help="Reuse already-built images (faster after the first).")
def fragments_batch(start: int, count: int, no_build: bool) -> None:
    """Record a diverse fragment library across a range of seeds in one pass.

    Each seed gets its own range, torn down before the next. One failed build does not abort
    the run; a per-seed summary and the library totals are printed at the end."""
    from iris.cli_ui import Progress, Spinner, fmt_dur, footer, header, result_line
    from iris.fragments.library import index_library
    from iris.live import deploy as d
    from iris.spikes.common import require_docker

    require_docker()
    for p in sorted(d.running_projects()):
        d.down_project(p)  # start from a clean machine

    header("IRIS · recording fragment library", f"{count} seeds (master {start} to {start + count - 1})")
    prog = Progress(total=count)
    recorded = 0
    groups: set[str] = set()
    errors: dict[int, str] = {}
    for i, master in enumerate(range(start, start + count), start=1):
        group = SeedSet.from_master(master).group_id()
        spin = Spinner(f"[{i}/{count}] {group}  starting…")
        with spin:

            def on_phase(ph: str, s: Spinner = spin, i: int = i, g: str = group) -> None:
                s.set_label(f"[{i}/{count}] {g}  {ph}…")

            try:
                frags = _record_one(master, no_build, on_phase=on_phase)
            except Exception as exc:  # keep going; one bad build must not stop the whole batch
                errors[master] = str(exc)
                prog.tick()
                result_line(False, f"[{i}/{count}] {group}", f"failed — {exc}", spin.elapsed, prog)
                continue
        prog.tick()
        recorded += len(frags)
        if frags:
            groups.add(group)
        labels: dict[str, int] = {}
        for f in frags:
            labels[f.truth.label] = labels.get(f.truth.label, 0) + 1
        detail = (
            f"{len(frags)} fragments (" + ", ".join(f"{n} {k}" for k, n in sorted(labels.items())) + ")"
            if frags
            else "no fragments (health gate did not pass)"
        )
        result_line(bool(frags), f"[{i}/{count}] {group}", detail, spin.elapsed, prog)

    idx = index_library()
    click.echo()
    click.secho(f"  library: {idx.total} fragments across {len(idx.by_group)} groups", bold=True)
    for fam, fr in sorted(idx.by_family.items()):
        click.secho(f"    {fam:20} {len(fr):4}", dim=True)
    ok = not errors
    footer(
        f"done · {len(groups)} ok, {len(errors)} failed · {recorded} new fragments · {fmt_dur(prog.elapsed)}",
        ok,
    )
    if errors:
        click.secho(
            f"  failed seeds: {sorted(errors)} (rerun: iris fragments record --master N)", fg="yellow"
        )
    sys.exit(0 if recorded else 1)


@fragments.command("list")
def fragments_list() -> None:
    """Summarise the fragment library on this machine."""
    from iris.fragments.library import index_library

    idx = index_library()
    click.echo(f"{idx.total} fragments across {len(idx.by_group)} groups")
    for fam, frags in sorted(idx.by_family.items()):
        labels: dict[str, int] = {}
        for f in frags:
            labels[f.truth.label] = labels.get(f.truth.label, 0) + 1
        click.echo(f"  {fam:20} {len(frags):4}  {labels}")


# ---------------------------------------------------------------- dataset (P7)


def _dataset_dir(out: Path | None) -> Path:
    return out or paths().store / "dataset"


def _ood_from_options(
    topology: str | None, industry: str | None, family: str | None, style: str | None
) -> Any:
    from iris.dataset.splits import OodConfig

    def s(v: str | None) -> frozenset[str]:
        return frozenset(x for x in (v or "").split(",") if x)

    return OodConfig(topologies=s(topology), industries=s(industry), families=s(family), grc_styles=s(style))


@main.group()
def dataset() -> None:
    """Assemble datasets: compose training packages, report splits, coverage and drift."""


@dataset.command("build")
@click.option("--start", type=int, default=0, show_default=True)
@click.option("--count", type=int, default=20, show_default=True)
@click.option("--ood-topology", help="Comma-separated held-out topology archetypes.")
@click.option("--ood-industry", help="Comma-separated held-out industries.")
@click.option("--ood-family", help="Comma-separated held-out attack families (F1..F9).")
@click.option("--ood-style", help="Comma-separated held-out GRC styles.")
@click.option("--reuse-cap", type=int, default=5, show_default=True, help="Max placements per fragment.")
@click.option(
    "--out", type=click.Path(file_okay=False, path_type=Path), help="Default: $IRIS_DATA/store/dataset"
)
def dataset_build(
    start: int,
    count: int,
    ood_topology: str | None,
    ood_industry: str | None,
    ood_family: str | None,
    ood_style: str | None,
    reuse_cap: int,
    out: Path | None,
) -> None:
    """Compose a training package per seed from the fragment library, then write the
    splits and coverage reports. Needs a recorded fragment library (iris fragments record)."""
    from iris.cli_ui import Spinner, fmt_dur, footer, header
    from iris.dataset.build import build_dataset, load_library

    library = load_library()
    if not library:
        raise click.ClickException("the fragment library is empty; record fragments first")
    ood = _ood_from_options(ood_topology, ood_industry, ood_family, ood_style)
    base = _dataset_dir(out)
    header("IRIS · building dataset", f"{count} seeds · library {len(library)} fragments")
    spin = Spinner("starting…")
    try:
        with spin:
            res = build_dataset(
                list(range(start, start + count)),
                library,
                ood,
                base,
                reuse_cap=reuse_cap,
                progress=spin.set_label,
            )
    except FileExistsError as exc:
        raise click.ClickException(str(exc)) from exc
    s = res.summary()
    cov = res.coverage
    click.secho(f"  packages        {s['packages']}", bold=True)
    click.echo(f"  in-distribution {s['in_distribution_groups']} groups")
    click.echo(f"  ood sets        {', '.join(sorted(res.splits.ood_sets)) or '—'}")
    click.echo(f"  episodes        {cov.episodes}  ({cov.by_verdict.get('malicious', 0)} with attacks)")
    click.echo(
        f"  decisions       D1={cov.decision_presence['D1']} D2={cov.decision_presence['D2']}"
        f" D4={cov.decision_presence['D4']} D6={cov.decision_presence['D6']}"
    )
    click.echo(f"  families        {cov.by_family or '—'}")
    for w in res.splits.warnings():
        click.secho(f"  warning: {w}", fg="yellow")
    footer(f"dataset ready at {base} · {fmt_dur(spin.elapsed)}")


@dataset.command("splits")
@click.option("--start", type=int, default=0, show_default=True)
@click.option("--count", type=int, default=50, show_default=True)
@click.option("--ood-topology")
@click.option("--ood-industry")
@click.option("--ood-family")
@click.option("--ood-style")
def dataset_splits(
    start: int,
    count: int,
    ood_topology: str | None,
    ood_industry: str | None,
    ood_family: str | None,
    ood_style: str | None,
) -> None:
    """Preview the split assignment for a range of seeds (no building)."""
    from iris.dataset.build import grc_style_signature
    from iris.dataset.splits import GroupProfile, build_splits
    from iris.generator.grc.recorded import build_grc
    from iris.generator.sampler import SampleOverrides, sample_spec
    from iris.live.attacks import applicable_families

    ood = _ood_from_options(ood_topology, ood_industry, ood_family, ood_style)
    profiles: dict[str, GroupProfile] = {}
    for m in range(start, start + count):
        seeds = SeedSet.from_master(m)
        spec = sample_spec(seeds, SampleOverrides(live=True))
        grc = build_grc(spec, seeds)
        profiles[seeds.group_id()] = GroupProfile(
            group_id=seeds.group_id(),
            topology=spec.archetype,
            industry=spec.organization.industry.value,
            families=tuple(applicable_families(spec)),
            grc_style=grc_style_signature(grc.style),
        )
    click.echo(json.dumps(build_splits(list(profiles.values()), ood).to_dict(), indent=2))


@dataset.command("coverage")
@click.argument("root", type=click.Path(exists=True, file_okay=False, path_type=Path))
def dataset_coverage(root: Path) -> None:
    """Coverage report over a built dataset's packages (reads the hidden evaluation keys)."""
    from iris.dataset.coverage import coverage_report, from_keys

    items = []
    for pkg in sorted(root.glob("scenario-*")):
        ek = pkg / "hidden" / "evaluation_key"
        if not ek.exists():
            continue
        full = json.loads((pkg / "hidden" / "manifest.json").read_text(encoding="utf-8"))
        tier = full.get("data_tier", "train")
        for d1_path in sorted((ek / "d1").glob("*.json")):
            eid = d1_path.stem
            d1 = json.loads(d1_path.read_text(encoding="utf-8"))
            d2 = json.loads((ek / "d2" / f"{eid}.json").read_text(encoding="utf-8"))
            d4 = json.loads((ek / "d4" / f"{eid}.json").read_text(encoding="utf-8"))
            d6_path = ek / "d6" / f"{eid}.json"
            d6n = (
                len(json.loads(d6_path.read_text(encoding="utf-8")).get("flaws", []))
                if d6_path.exists()
                else 0
            )
            items.append(from_keys(d1, d2, d4, tier, d6n))
    click.echo(json.dumps(coverage_report(items).to_dict(), indent=2))


@dataset.command("coverage-context")
@click.argument("root", type=click.Path(exists=True, file_okay=False, path_type=Path))
def dataset_coverage_context(root: Path) -> None:
    """Coverage over a context-tier store (e.g. store/context): reads the D6 keys only.

    Use this for packages built by ``iris package batch`` (no telemetry, D6 only).
    For a full dataset built by ``iris dataset build`` use ``coverage`` instead.
    """
    from iris.dataset.coverage import context_coverage_report

    keys: list[dict[str, object]] = []
    packages = 0
    for pkg in sorted(root.glob("scenario-*")):
        d6_dir = pkg / "hidden" / "evaluation_key" / "d6"
        if not d6_dir.exists():
            continue
        packages += 1
        for kp in sorted(d6_dir.glob("*.json")):
            keys.append(json.loads(kp.read_text(encoding="utf-8")))
    if packages == 0:
        raise click.ClickException(
            f"no context packages with D6 keys under {root}; "
            "build some with `iris package batch --count N --out <dir>`"
        )
    report = context_coverage_report(keys, packages=packages)
    click.echo(json.dumps(report.to_dict(), indent=2))


@dataset.command("drift")
@click.argument("reference", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("candidate", type=click.Path(exists=True, file_okay=False, path_type=Path))
def dataset_drift(reference: Path, candidate: Path) -> None:
    """Compare a candidate (composed) dataset against a reference (live Gold) with the
    Part 8 drift tests. Exit non-zero when the candidate fails."""
    from iris.dataset.drift import drift_report
    from iris.dataset.features import dataset_features

    rep = drift_report(dataset_features(reference), dataset_features(candidate))
    click.echo(json.dumps(rep.to_dict(), indent=2))
    sys.exit(0 if rep.ok else 1)


@dataset.command("pack")
@click.argument("store", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--out",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="output dir (default: STORE's parent)",
)
@click.option("--name", default="iris_d6_dataset", help="base name for the packed files")
def dataset_pack(store: Path, out: Path | None, name: str) -> None:
    """Pack a context store into one compressed archive + a compact label index.

    Produces ``<name>.tar.xz`` (the whole dataset, ~30x smaller, stdlib LZMA — works offline)
    and ``<name>.labels.jsonl.xz`` (one line per episode with its D6 ground truth, for the
    training pipeline). Deterministic: same dataset, same bytes.
    """
    from iris.dataset.pack import pack_dataset

    result = pack_dataset(store, out or store.parent, name)
    click.echo(json.dumps(result.to_dict(), indent=2))


# ---------------------------------------------------------------- spikes (P1)


def _report(result: Any) -> None:
    colours = {"pass": "green", "fail": "red", "info": "cyan", "skip": "yellow"}
    click.echo(f"\n== spike: {result.spike}")
    for c in result.checks:
        value = "" if c.value is None else f" = {c.value}"
        detail = f"  ({c.detail})" if c.detail else ""
        click.secho(f"  {c.status:5} {c.name}{value}{detail}", fg=colours.get(c.status))
    for e in result.errors:
        click.secho(f"  ERROR {e}", fg="red")
    click.secho(
        f"  -> {'PASS' if result.passed else 'FAIL'}   results: {result.measurements.get('run_dir')}",
        fg="green" if result.passed else "red",
    )


@main.group()
def spike() -> None:
    """P1 measurement spikes (need Docker and internet)."""


@spike.command("wazuh")
@click.option("--no-build", is_flag=True, help="Reuse existing images.")
@click.option("--keep", is_flag=True, help="Leave containers running for inspection.")
def spike_wazuh(no_build: bool, keep: bool) -> None:
    """Wazuh boot/RAM, correlation, export time shift, warm restart into a later window."""
    from iris.spikes import wazuh

    result = wazuh.run(build=not no_build, keep=keep)
    _report(result)
    sys.exit(0 if result.passed else 1)


@spike.command("network")
@click.option("--no-build", is_flag=True, help="Reuse existing images.")
@click.option("--keep", is_flag=True, help="Leave containers running for inspection.")
@click.option("--suricata-image", default="jasonish/suricata:8.0.6", show_default=True)
def spike_network(no_build: bool, keep: bool, suricata_image: str) -> None:
    """Router + Suricata in the router namespace: paths, duplicates, dedup, drops, time shift."""
    from iris.spikes import network

    result = network.run(build=not no_build, keep=keep, suricata_image=suricata_image)
    _report(result)
    sys.exit(0 if result.passed else 1)


@spike.command("all")
@click.option("--no-build", is_flag=True)
def spike_all(no_build: bool) -> None:
    """Run every spike in sequence."""
    from iris.spikes import network, wazuh

    results = [wazuh.run(build=not no_build), network.run(build=not no_build)]
    for r in results:
        _report(r)
    sys.exit(0 if all(r.passed for r in results) else 1)


# ---------------------------------------------------------------- synth (synthetic path)


@main.group()
def synth() -> None:
    """Synthetic scenario generation (no Docker): build v2.1 SYN packages."""


def _synth_dir(out: Path | None) -> Path:
    base = out or paths().store / "synth"
    base.mkdir(parents=True, exist_ok=True)
    return base


@synth.command("build")
@click.option("--master", type=int, required=True)
@click.option("--noise", type=click.Choice(["low", "medium", "high"]), default="medium", show_default=True)
@click.option(
    "--out", type=click.Path(file_okay=False, path_type=Path), help="Default: $IRIS_DATA/store/synth"
)
def synth_build(master: int, noise: str, out: Path | None) -> None:
    """Build one synthetic v2.1 package (context + posture + telemetry + noise) and verify it."""
    from iris.packager.verify import verify_package
    from iris.synth.build import build_synth_scenario, write_synth_scenario

    built = build_synth_scenario(SeedSet.from_master(master), noise_level=noise)
    try:
        res = write_synth_scenario(built, _synth_dir(out))
    except FileExistsError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"{res.package_id}  {res.root}")
    click.echo(
        f"  malicious activities {built.n_malicious}, telemetry records {built.n_telemetry}, noise {noise}"
    )
    click.echo(f"  visible files {res.visible_files}, hidden files {res.hidden_files}")
    _verdict(verify_package(res.root))


@synth.command("batch")
@click.option("--start", type=int, default=0, show_default=True)
@click.option("--count", type=int, default=20, show_default=True)
@click.option("--noise-mix", default="30/40/30", show_default=True, help="low/medium/high percentages")
@click.option(
    "--out", type=click.Path(file_okay=False, path_type=Path), help="Default: $IRIS_DATA/store/synth"
)
def synth_batch(start: int, count: int, noise_mix: str, out: Path | None) -> None:
    """Build and verify many synthetic packages; report counts and determinism-friendly stats."""
    import time as _time

    from iris.packager.verify import verify_package
    from iris.synth.build import build_synth_scenario, write_synth_scenario
    from iris.synth.qa.batch import noise_for_index

    try:
        lo, mid, hi = (int(x) for x in noise_mix.split("/"))
    except ValueError as exc:
        raise click.ClickException("noise-mix must look like 30/40/30") from exc
    mix = {"low": lo / 100, "medium": mid / 100, "high": hi / 100}
    base = _synth_dir(out)
    t0 = _time.perf_counter()
    failed = built = total_tel = total_mal = 0
    counts = {"low": 0, "medium": 0, "high": 0}
    for i in range(count):
        level = noise_for_index(i, mix)
        counts[level] += 1
        b = build_synth_scenario(SeedSet.from_master(start + i), noise_level=level)
        root = base / f"scenario-{b.assembled.scenario_id}"
        if not root.exists():
            write_synth_scenario(b, base)
            built += 1
        if not verify_package(root).ok:
            failed += 1
            click.secho(f"verify FAILED: {root}", fg="red")
        total_tel += b.n_telemetry
        total_mal += b.n_malicious
    secs = _time.perf_counter() - t0
    click.echo(f"{count} SYN packages in {base} ({built} new) in {secs:.1f}s; verify failures: {failed}")
    click.echo(f"  noise mix {counts}; telemetry records {total_tel}; malicious activities {total_mal}")
    sys.exit(1 if failed else 0)


@synth.command("validate")
@click.argument("root", type=click.Path(exists=True, file_okay=False, path_type=Path))
def synth_validate(root: Path) -> None:
    """Integrity + contract + no-peek audit of a synthetic package."""
    from iris.packager.verify import verify_package

    click.echo(str(root))
    _verdict(verify_package(root))


@synth.command("inspect")
@click.option("--master", type=int, required=True)
@click.option("--noise", type=click.Choice(["low", "medium", "high"]), default="medium")
def synth_inspect(master: int, noise: str) -> None:
    """Summarise a synthetic scenario without writing it (counts per sensor and truth)."""
    from iris.synth.build import build_synth_scenario

    b = build_synth_scenario(SeedSet.from_master(master), noise_level=noise)
    vis = b.assembled.visible
    click.echo(
        f"scenario {b.assembled.scenario_id}  org {b.assembled.spec.organization.industry.value} "
        f"size {b.assembled.spec.organization.size.value}"
    )
    for key in sorted(vis):
        if key.startswith("telemetry/") and isinstance(vis[key], list):
            click.echo(f"  {key}: {len(vis[key])}")
    click.echo(f"  malicious activities (hidden): {b.n_malicious}")


@synth.group("qa")
def synth_qa() -> None:
    """Release-gate quality checks for synthetic batches."""


@synth_qa.command("shortcut")
@click.option("--count", type=int, default=30, show_default=True)
@click.option("--start", type=int, default=0, show_default=True)
def synth_qa_shortcut(count: int, start: int) -> None:
    """Anti-fingerprint shortcut test: a trivial model must NOT separate attack from benign."""
    from iris.synth.qa.batch import run_shortcut

    result, batch = run_shortcut(count, start)
    click.echo(json.dumps(result.to_dict(), indent=2))
    click.echo(f"noise mix: {batch.level_counts}")
    if result.passed:
        click.secho("shortcut test PASSED (data does not leak the generator)", fg="green")
    else:
        click.secho("shortcut test FAILED: increase noise/hard negatives; do not weaken thresholds", fg="red")
    sys.exit(0 if result.passed else 1)


# ---------------------------------------------------------------- checks


@main.command("check")
def check() -> None:
    """Run the architecture checks (real-clock ban, import boundaries)."""
    from iris.devtools.boundaries import main as boundaries_main

    sys.exit(boundaries_main([str(repo_root() / "src")]))


if __name__ == "__main__":
    main()
