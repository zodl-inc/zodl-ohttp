# Security Policy

ZODL OHTTP (this repository: the gateway, the relay simulator, the `zodl-ohttp-client` library,
the end-to-end client and the fuzz targets) follows the security disclosure policy of the Zcash
Open Development Lab (ZODL), which conforms to
https://github.com/RD-Crypto-Spec/Responsible-Disclosure.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

- **Critical vulnerabilities** (for this repository: anything that lets a relay or a third party
  read the content of a wallet's requests or responses, lets the gateway learn a client's network
  address, or allows a remote compromise of the gateway or of a wallet through the client
  library): create a new Signal group with the ZODL security contacts

  ```
  dairaemma.31
  nuttycom.01
  ```

  Do not reuse a previous group for a new issue. ZODL does not accept security reports by
  e-mail: e-mail is not suitable for this purpose for reliability and security reasons, even when
  encrypted.

- **All other vulnerabilities**: use GitHub's "Report a vulnerability" feature on this repository
  (Security tab, private vulnerability reporting).

ZODL is committed to working with researchers who report vulnerabilities to resolve them on an
appropriate timeline, to coordinate the release, and to credit the reporter if they wish.

Please rate the severity honestly. ZODL's severity rubric (critical, high, moderate, low) is the
one published in the ZODL security policy; overstating a finding's severity makes the reporter
ineligible for any compensation.

## Scope notes

- Relay secrets, HPKE private keys and the key-configuration signing seed are never committed;
  they are provided to the gateway through its environment. A report that one of them is exposed
  by this code is in scope.
- The repository carries no deployment key. The key-configuration signing **public** keys a
  wallet trusts are build-time variables (`ZODL_OHTTP_SIGNING_PUBKEY_MAINNET` / `_TESTNET`, see
  `client/INTEGRATION.md`) and are public by design; so are the test seeds and keys in
  `docs/signed-configs-test-vector.json` and in the tests.
- Operational findings about a specific deployment (rate limits, edge configuration) are welcome
  through the same channels.

## Supported versions

The `main` branch and the images built from it are supported. Older tags receive fixes only
when they are still deployed.
