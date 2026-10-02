# Upstream integration — 2026-10-02

## Sources and scope

- Maintained fork baseline: `7bada31e4d66df00f7b74d33cdaeacaf3ca31968`.
- Upstream: `Arcadia-1/virtuoso-bridge-lite`, `main` at `cf6344cff410bcbd32fd6fe595a53d1fdbeeb7c3`.
- Ordered preparation commits: `1d1c964` (X11 title decoding and CIW discovery), `48b4554` (layout summary return).
- Integrated schematic manifest/staged import and diagnostics, Maestro history locks/session state/Monte Carlo, documentation host routing and doc-info, shared-CIW dialog inspection/guard, HMAC authentication/nonces/PID discovery, port handling, IPC logging configuration, and optional Cliosoft SOS APIs/CLI.
- Upstream traffic statistics were excluded. SOS was included following the updated user instruction.

## Fork compatibility decisions

The fork retains protocol v3 complete-frame checks, operation/request identity, serial admission and exclusive requests, persisted ledger, late-response draining, quarantine/recovery policies, staged deployment, script receipts, and guarded window input.

Signed-v1 upstream clients remain supported. Signed-v3 clients use a separate `vb3-request` MAC over the complete canonical request, including request identity, operation class and exclusive admission. Both `mac` and `frame_mac` carry this digest. Removing metadata cannot downgrade a signed-v3 request to signed-v1. Cached v3 replies are signed again for the new nonce without executing the operation again. The explicit existing profile-token protocol remains available for compatibility.

The upstream early timeout-reader return was not used: the fork must keep draining and collecting terminal proof after timeout. Authentication failures before dispatch are `not_dispatched`; unverifiable replies after dispatch remain unknown and are never automatically replayed.

A listener without saved state can be avoided by choosing another local port. Reusing a saved tunnel still requires the fork's complete profile identity and live process checks. Incomplete legacy state is rejected. Windows liveness checks use the existing Win32 process probe rather than `os.kill(pid, 0)`.

Diagnostics read existing authentication material without provisioning secrets. Token provisioning and remote-port probes use bounded budgets. Successful staged schematic saves explicitly return `t` for the fork's save-receipt validation.

## Validation and limits

- Changed-file offline suite: **836 passed, 18 skipped**. Focused final authentication/timeout/tunnel suite: **192 passed, 5 skipped**. SOS subset: **264 passed, 2 skipped** (included in the changed-file suite).
- Added shipped-daemon/client loopback tests for full metadata signatures, protocol downgrade rejection, signed response tampering, and cached request-ID replay without readmission.
- Existing daemon queue/timeout/late-drain tests retained; no simulation or CAD design was modified by these checks.
- Python source checked with Python 3.9 grammar; this is not execution under Python 3.9 or Python 2.7.
- Full offline Windows run: 1816 passed, 61 failed, 32 skipped, 1 deselected. Baseline archive run: 1196 passed, 67 failed, 17 skipped, 1 deselected. Failures include unavailable POSIX tools, symlink privileges, path semantics and unstable artifact-publication fixtures. Failure sets vary between runs; these results do not establish a green full suite or prove every residual failure pre-existing. Layout streamout implementation and its tests were unchanged by this merge.
- SOS tests use simulated command/session responses. No real SOS installation, license, workarea, checkout, checkin or cancel-checkout was exercised.
- No live Virtuoso restart, daemon activation, CAD/PDK acceptance, or GitHub push was performed.

## Activation boundary

This is a source integration. Deploy/activate the matching client and packaged daemon together before relying on the new authenticated factories. An old running daemon may reject the new handshake; do not enable unauthenticated mode to bypass this. Use the existing guarded deployment/restart workflow after separate authorization, then verify source/runtime identity and read-only execution.

The parent repository's gitlink and `tools/dependencies/bridge.json` remain pinned to the previous release pending a coordinated publication. Do not publish a parent pin to a commit that has not been pushed to the maintained fork.
