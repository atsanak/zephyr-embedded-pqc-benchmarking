# Security policy

This is a source-visible engineering portfolio and evaluation repository, not a
certified cryptographic module or a supported production distribution.

Please do not open a public issue for a suspected vulnerability that would put
users, keys, devices, or unpublished research at risk. Use GitHub's private
vulnerability reporting feature for this repository. Include the affected
component, revision, reproduction conditions, expected impact, and any
temporary mitigation you have validated.

The following are explicitly outside the assurance claims of this public cut:

- formal constant-time proof;
- physical side-channel resistance;
- production entropy quality across every Zephyr target;
- certification under FIPS 140, Common Criteria, or a similar scheme;
- production hardening of the demonstration fleet key-file provider; and
- physical-board performance claims for results labelled QEMU or build-only.

Good-faith reports will be investigated against the exact revision and
configuration supplied by the reporter.
