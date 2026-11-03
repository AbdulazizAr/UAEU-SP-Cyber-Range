"""Live range runner (P2): build images, deploy a compiled enterprise, health-gate it,
tear it down. One scenario at a time per lane; every Docker object carries the
``iris.project`` label so teardown is run-scoped and verifiable."""
