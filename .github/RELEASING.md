# Releasing openvpn-otp-auth

Publishing a GitHub release from `main` starts the guarded stable-release path.
The release tag must initially resolve to the current `main` commit. The
workflow builds and tests an isolated candidate with the requested version,
then validates the bounded candidate artifact against the trusted source before
creating `Release vX.Y.Z`. It advances `main` and replaces the release tag with
an annotated tag in one leased atomic push.

If a stable run fails before promotion, neither `main` nor the release tag is
changed. Correct the source or release metadata and publish a new release only
after the tag again points to the current `main` commit. If promotion completed
but PyPI publication failed, rerun the same workflow: it accepts only the
matching one-parent `Release <tag>` commit already reachable from `main`,
rebuilds and revalidates its candidate artifact, and publishes that verified
artifact without moving either ref again.

Prereleases must already be matching commits reachable from `main`; they are
validated without mutating refs or publishing to a registry. The intentional
manual `workflow_dispatch` path remains the route for TestPyPI publication.
