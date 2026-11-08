"""Synthetic scenario generation (builder brief files 00-09).

Replaces the live Docker range: a scenario's telemetry, posture and truth are derived
deterministically from one simulated :class:`iris.synth.world.World`, with no Docker, no
real Wazuh/Suricata/Trivy at generation time. Produces Input-Agreement v2.1 packages
(v2.0 visible plane + hidden noise additions).

Generator-side package: imports core, contracts, generator, references, oracle, packager;
never the Engine or the evaluator (enforced by ``iris.devtools.boundaries``).
"""

SYNTH_VERSION = "synth-0.1.0"
