"""``iris`` command line."""

from __future__ import annotations

import json
import sys
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
    """Re-hash every reference against the lock."""
    from iris.references.registry import load_lock, load_registry, verify

    results = verify(load_registry(), load_lock())
    for r in results:
        colour = {"ok": "green", "mismatch": "red"}.get(r.status, "yellow")
        click.secho(f"{r.status:9} {r.id} {r.detail}", fg=colour)
    sys.exit(1 if any(r.status == "mismatch" for r in results) else 0)


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
            summary = json.loads(path.read_text())["summary"]
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


@eval_.command("d6")
@click.argument("root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--decisions", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
def eval_d6(root: Path, decisions: Path) -> None:
    """D6 recall by detectability class, precision, type accuracy, false alarms, Brier."""
    from iris.contracts.decisions import DecisionRecord
    from iris.evaluator.d6 import score_package

    recs = [
        DecisionRecord.model_validate_json(line)
        for line in decisions.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    click.echo(json.dumps(score_package(root, recs).summary(), indent=2))


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
def range_up(master: int, keep: bool, no_build: bool) -> None:
    """Deploy one live enterprise, run the health gate, tear down (unless --keep)."""
    from iris.live.gate import run_once

    sm = run_once(master, keep=keep, build=not no_build)
    _print_summary(sm)
    sys.exit(0 if sm.healthy and not sm.leftovers else 1)


@range_.command("down")
@click.argument("project", required=False)
@click.option("--all", "all_", is_flag=True, help="Every iris project on this machine.")
def range_down(project: str | None, all_: bool) -> None:
    """Remove a kept range (all containers, networks and volumes with its label)."""
    from iris.live.deploy import down_project, running_projects

    targets = sorted(running_projects()) if all_ else [project] if project else []
    if not targets:
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


@range_.command("gate")
@click.option("--start", type=int, default=0, show_default=True)
@click.option("--count", type=int, default=20, show_default=True, help="Seeds that must actually run.")
def range_gate(start: int, count: int) -> None:
    """P2 exit gate: COUNT seeds must deploy, pass health and tear down cleanly.

    Seeds whose subnets collide with networks already on this machine are skipped and
    replaced by the next seed (a lane problem, not a range failure).
    """
    from iris.live.gate import run_once

    results: list[Any] = []
    skipped: list[Any] = []
    m = start
    while len(results) < count and m < start + count * 3:
        sm = run_once(m, build=True)
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


# ---------------------------------------------------------------- checks


@main.command("check")
def check() -> None:
    """Run the architecture checks (real-clock ban, import boundaries)."""
    from iris.devtools.boundaries import main as boundaries_main

    sys.exit(boundaries_main([str(repo_root() / "src")]))


if __name__ == "__main__":
    main()
