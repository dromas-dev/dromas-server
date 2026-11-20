# Security

**The protocol is designed against this server system.** Clients treat it as possibly hostile: a mailbox checks every signature, prekey and revocation itself, and believes nothing a server system says. So what protects a message is not in this repo. It is in [dromas-client](https://github.com/dromas-dev/dromas-client), whose [`SECURITY.md`](https://github.com/dromas-dev/dromas-client/blob/main/SECURITY.md) maps each promise a mailbox is given to the code and tests that hold it. This file covers what `dromas-server` itself must get right, and how to report where it does not.

## Supported versions

**Dromas is pre-v1, and only the latest release and the latest commit on `main` are supported.** A fix is a commit on `main`, released as the next patch. The major version is the protocol's, shared with the client, so both are 0.x until the protocol is frozen, and v1 together; minors and patches are each repo's own.

## Reporting a vulnerability

**Report it privately, with GitHub's private vulnerability reporting:** the **Report a vulnerability** button under this repo's Security tab, or from a terminal:

```sh
gh api repos/dromas-dev/dromas-server/security-advisories/reports \
  -f summary='…' -f description='…'
```

- **Here:** `dromas-server`, and dromas.dev as it is run.
- **The protocol, the clients or the vectors:** dromas-client, by the same route. Not sure which? Either one.
- **How to write one, what is not a vulnerability, and what happens next:** dromas-client's [`SECURITY.md`](https://github.com/dromas-dev/dromas-client/blob/main/SECURITY.md). It applies here as written. Its § Decided questions lists the security questions already decided, for this server system too, each with its reasoning and the issue that decided it. A way around a limit that `LIMITS.md` does not already list as a known weakness is a vulnerability.

## What `dromas-server` must get right

Each row is one claim and what holds it: the code that keeps the claim, then the tests that try to break it, grouped by file. A row whose claim, or part of it, no test holds says so. The whole rule is in the section or the doc comments that the row names.

| The claim | Held by |
|---|---|
| **Server ignorance:** `dromas-server` holds no private key, no plaintext and no message signature, and issues no credential, so a copy of its database lets nobody read or sign a message | `PROTOCOL.md` §13; `Header` in `internal/server/store.go`, `routes` in `internal/server/server.go`; `internal/server/server_test.go`: `TestSendPipeline` (the ciphertext kept as sent, no sender listed), `TestOwnerCalls` (no route issues a credential); `internal/server/api_test.go`: `TestTheRoutesAreTheDescriptions` |
| **Mailbox authorization:** only a pass that the mailbox's identity, or the certificate of its current or newly sent prekey statement, signed acts for a mailbox, at the one server the pass names | `PROTOCOL.md` §8; `passCheck`, `checkSigner` and `serverName` in `internal/server/pass.go`; `internal/server/server_test.go`: `TestOwnerCalls`, `TestPrekeyRenewal`, `TestAPassIsForOneServer`, `TestTwoAuthorizationLinesAreNoPass`; `internal/server/signers_test.go`: `TestTheIdentitysPassIsAlwaysTaken`; `internal/server/keytype_test.go`: `TestACertificateOnRecordThatTheIdentityDidNotSign`; `internal/server/passrefused_test.go`: `TestAPassOfEitherForm`, `TestARevokedCurrentCertificateIsAnsweredBeforeThePass`; `internal/server/gate_test.go`: `TestAPassHasOneFormAndBothValuesOfS` |
| **Revocations kept:** `dromas-server` keeps every verified revocation for good and serves it to anyone, and stores no statement and registers no address that a committed revocation covers, and serves no message it covers | `PROTOCOL.md` §11.15; `pgBackend.Revoke` and `CreateMailbox` in `internal/server/postgres.go`, `internal/server/held.go`, migrations `internal/server/migrations/00004_revocations_kept.sql` and `00006_revocations_never_deleted.sql`; `internal/server/revocation_test.go`: `TestARevocationIsKeptWithNoMailbox`, `TestTheRevocationsOfAnyAddressAreServed`; `internal/server/migrate_test.go`: `TestTheRuntimeRoleCannotTakeARevocationBack` (no role `serve` runs as deletes one); `internal/server/revokedcerts_test.go`: `TestRevokedCertificates`; `internal/server/carried_test.go`: `TestEvery410CarriesTheRecord`; `internal/server/boxcache_test.go`: `TestEveryOrderOfAFillAndAWrite` (memory never drops a revocation it saw); `internal/server/crossprocess_test.go`: `TestAProcessBehindStoresNothingForAnAddressRevokedElsewhere`, `TestARevocationCommittedDuringASendsWriteLeavesARowNeverServed`, `TestAProcessBehindTakesNoRenewalUnderACertificateRevokedElsewhere`, `TestAProcessBehindRegistersNoAddressRevokedElsewhere`; `internal/server/outcomes_test.go`: `TestARevocationWhoseAnswerWasLostIsInTheNextPassCheck` |
| **Retention:** an ack deletes a message, every message expires 7 days less an hour and two minutes after `dromas-server` receives it, and `dromas-server` serves no message past its expiry | `PROTOCOL.md` §13; `retire` in `internal/server/postgres.go`, `sweepExpired` in `internal/server/postgres_sweep.go`; `internal/server/server_test.go`: `TestSendPipeline` (an ack, then nothing listed); `internal/server/store_test.go`: `TestAckedMessageWithABodyAgainIsGone`, `TestCrashBetweenAnAcksDeletes`, `TestExpiredHeadersAreNotListed`; `internal/server/postgres_backend_test.go`: `TestTheSweepDeletesWhatHasExpired` |
| **Abuse limits:** `dromas-server` counts every request against its IP address before doing any work for it, and a caller spends a mailbox's budget only once its pass or message has passed every check | `LIMITS.md` § The rule; `gate`, `mount` and `boxsCall` in `internal/server/server.go`; `internal/server/gate_test.go`: `TestEveryRequestIsCountedBeforeAnythingIsDone`, `TestANewPassSpendsItsAddresssFloodBudget`; `internal/server/budgets_test.go`: `TestLookupsArePaidByTheirCaller`, `TestFailedPassesAreCountedPerCaller`, `TestTheReceiveBudget`; `internal/server/quotas_test.go`: `TestEveryRefusalNamesItsLimit` |
| **Minimal logs:** no log line or metric carries a mailbox address, a message id or a client's IP address, and a log names each long value by a keyed hash under a key replaced daily | `PROTOCOL.md` §13; `redact`, `logNamer` and `loggedPath` in `internal/server/server.go`, `NewMetrics` in `internal/server/metrics.go`; `internal/server/log_test.go`: `TestNoLogLineCarriesAnAddress`, `TestTheAccessLogWritesWhatTheRoutersMatched`, `TestTheAWSSDKsLinesAreRedacted`, `TestTheKeyIsReplacedAfterADay`, `TestTwoKeysGiveTwoNamesAndNoneIsTheValuesSHA256`; `internal/server/metrics_test.go`: `TestMetricsCarryNoCallerValue` |
| **Release provenance:** a release is built by this repo's workflow from a tag an allowed signer signed, after CI passes, with its files and image attested, its checksums signed and its build reproduced | `.github/workflows/release.yml` jobs `tag` (`git verify-tag` against `.github/allowed_signers` as the tagged commit holds it), `ci`, `verify` and `rebuild`; `.goreleaser.yaml`; the tag ruleset (only an org admin makes a `v*` tag) and immutable releases, settings of the repo that no test reads |

**What is not tested:** that no log line carries a client's IP address.

**Run them:** `README.md` § Build and run.

**Where the rest is:** the threat model, what a server system can and cannot do, and the residual risks are the client repo's [`PROTOCOL.md`](https://github.com/dromas-dev/dromas-client/blob/main/PROTOCOL.md) §15, Security considerations; the questions for an outside reviewer are the client repo's issue #35. Every limit and where it is weak is [`LIMITS.md`](LIMITS.md); start there to break one.
