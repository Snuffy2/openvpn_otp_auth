# Releasing openvpn-otp-auth

Publishing a GitHub release from `main` starts the guarded stable-release path.
The release tag must initially resolve to the current `main` commit and use two
to four numeric components, such as `v1.2`, `v1.2.3`, or `v1.2.3.4`; accepted
prerelease tags add `aN`, `bN`, or `rcN`. The workflow builds an isolated
candidate with the requested version, validates the bounded wheel and sdist
against trusted source, then publishes the candidate to a temporary branch.
It dispatches the existing locked `review` and pytest gates for that exact
candidate SHA before creating `Release vX.Y.Z` and atomically advancing `main`
with an annotated release tag.

The reusable distribution core proves the exact wheel/sdist pair, safe archive
members and bounds, package metadata including Requires-Python, pure-wheel
compatibility, and wheel RECORD hashes. This repository's candidate verifier
then proves the OpenVPN-specific trusted-source payload, generated metadata,
dependencies, readme, SOURCES.txt, test manifest, and ZIP64 policy across the
candidate handoff. Those source comparisons are intentionally local to this
cross-job promotion workflow; they are not assumptions made by the shared
archive checker.

If a stable run fails before promotion, neither `main` nor the release tag is
changed. Correct the source or release metadata and publish a new release only
after the tag again points to the current `main` commit. If promotion completed
but PyPI publication failed, rerun the same workflow: it accepts only the
matching one-parent `Release <tag>` commit already reachable from `main`,
rebuilds and revalidates its candidate artifact, and publishes that verified
artifact without moving either ref again. The temporary validation branch is
deleted only after PyPI confirms publication; a failed upload retains it for
diagnosis.

Prereleases must already be matching commits reachable from `main`; they are
validated against the same exact-SHA review and pytest gates without mutating
refs or publishing to a registry. The intentional manual `workflow_dispatch`
path remains the route for TestPyPI publication.
