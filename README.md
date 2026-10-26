# ANKH Static Build Factory

This public repository contains static, reviewed workflow tooling. Routine requests change only `daemon/`, `pet/`, and `BUILD_REQUEST.json`; the policy job rejects every other path and any private or secret-like content. The workflow has no credential for the private repository. Each final bundle records its SHA-256 in an immutable artifact name tied to the exact workflow run; the public Release is only an anonymous download carrier for those digest-checked bytes.
