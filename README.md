# ANKH Encrypted Build Worker

This public repository is a workflow-only build worker. It contains no plaintext product source, no plaintext product binaries, no private repository credentials and no private build diagnostics.

Each request consists of authenticated ciphertext plus generic integrity metadata. Windows and macOS GitHub-hosted runners decrypt only inside ephemeral runner storage, run tests and builds with compiler output redirected away from public logs, then publish encrypted result bundles. A separate private broker authenticates and decrypts those bundles before publishing them to a private distribution repository.

Do not add product source, binaries, pull-request workflows, caches or plaintext build artifacts to this repository.

No license is granted for any encrypted payload or resulting product.
