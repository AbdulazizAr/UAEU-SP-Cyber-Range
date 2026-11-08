"""IRIS: synthetic SOC/GRC cyber range, dataset generator and evaluation harness."""

__version__ = "0.1.0"

#: Major version of the generator. Part of every sub-seed and group_id, so a major
#: bump intentionally produces new enterprises from the same master seed.
GENERATOR_MAJOR = 0

#: Data contract version (IRIS Input Agreement v2.0) used by the frozen live/compose path.
CONTRACT_SCHEMA_VERSION = "2.0.0"

#: Contract version produced by the synthetic path: v2.1 = v2.0 + hidden noise additions
#: (builder brief §4). Additive/minor; every v2.0 visible file name and field is kept.
SYNTH_SCHEMA_VERSION = "2.1.0"

#: Scenario spec format version.
SPEC_VERSION = "0.1.0"
