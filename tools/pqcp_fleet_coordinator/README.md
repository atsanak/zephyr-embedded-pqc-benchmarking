# PQCP Fleet Coordinator

`pqcp-fleet` is the offline-first control plane for the Zephyr fleet trust
protocol. It stores inventory and rollout state in SQLite/WAL, consumes
firmware-generated signed canonical-CBOR enrollment requests, issues
firmware-compatible ML-DSA-65 vouchers and credentials, publishes signed
policy and revocation epochs, and evaluates deterministic canary rollouts.

## Build

```sh
cargo build --release
```

The signing root is encrypted at rest. Set a non-interactive passphrase before
creating or loading it:

```sh
export PQCP_FLEET_KEY_PASSPHRASE='replace-with-a-secret-from-your-vault'
cargo run -- init
```

The key file uses Argon2id and XChaCha20-Poly1305 and is installed with mode
`0600` on Unix. The file provider is for local operation. Production
deployments should replace it with an HSM, PKCS#11, secure-element, or managed
signing provider without changing the protocol codec.

## Serve

```sh
cargo run -- serve --listen 127.0.0.1:8787
```

Important endpoints:

- `POST /v1/enroll`: JSON containing `request_cbor_b64`, where the decoded
  value is the exact signed `pqcp_fleet_enrollment_request`.
- `GET /v1/devices`: current fleet inventory.
- `POST /v1/policies`: create a signed policy epoch.
- `POST /v1/revocations`: issue a signed credential, device, or domain
  revocation update for a target device.
- `POST /v1/rollouts`: start a deterministic canary.
- `POST /v1/rollouts/{id}/observations`: report measured device outcomes.
- `GET /v1/events/stream`: server-sent operational events.

The root page provides a compact live fleet view. The REST API and CLI remain
the authoritative operator interfaces.

## Operator flow

```sh
cargo run -- admit edge-device-001 industrial-gateway \
  <factory-fingerprint-hex> <hardware-id-digest-hex> \
  --capabilities 63
cargo run -- enroll device-enrollment.cbor \
  --output-dir issued/edge-device-001
cargo run -- policy publish \
  --profile hybrid768-65-runtime \
  --canary-percent 10
cargo run -- policy list
cargo run -- rollout start <policy-id>
cargo run -- rollout show <rollout-id>
cargo run -- revoke edge-device-001 credential <credential-id> --reason 1
cargo run -- revocations
cargo run -- devices
cargo run -- status
```

The offline `enroll` command verifies the firmware signature, admission,
domain, lifetime, and replay counters before writing an atomic bundle containing
the ownership voucher, operational credential, fleet root public key, and JSON
response. The REST enrollment endpoint calls the same issuance service, so
offline and connected operation cannot drift.

Rollouts emit the explicit state path `draft`, `canary`, `observing`,
`promoting`, `draining`, and `completed`; threshold or deadline violations end
in `rolled_back`. Policy and revocation artifacts use the same two-array CBOR
envelope/payload shape and the same `PQCP-FLEET-CBOR-V1` ML-DSA context as the
firmware implementation. A durable coordinator sequence allocator keeps every
issued artifact ahead of device replay counters, including across restarts.
