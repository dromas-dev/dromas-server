# Contributing

## Sign off every commit

This project uses the [Developer Certificate of Origin](https://developercertificate.org/) (DCO), version 1.1. Every commit carries a `Signed-off-by:` line with the name and email of the person submitting it:

```sh
git commit -s
```

By adding that line you certify the statement below for that commit. A pull request whose commits lack it fails the DCO check and is not merged. To add it to commits already made:

```sh
git commit --amend -s --no-edit     # the last commit
git rebase --signoff main           # every commit on your branch
git push --force-with-lease         # then update the pull request
```

**If an AI agent wrote the change, the sign-off is still yours.** You certify the change and answer for it, however it was written. An agent may run `git commit -s` for you once you have told it to: that writes the line from your git identity. It never signs as itself, and never writes the line by hand. Name the tool in a `Co-Authored-By:` or `Assisted-by:` trailer. The maintainer's own commits name Custos, the maintainer's AI assistant, that way, and carry the maintainer's sign-off.

## Licence of contributions

A contribution to this repo is made under this repo's licence, Apache-2.0 (`LICENSE`). There is no contributor licence agreement.

The client, [dromas-client](https://github.com/dromas-dev/dromas-client), is Apache-2.0 too.

## Where a change goes

- **The wire, a check or a refusal:** the specification, `PROTOCOL.md` in the client repo, with the client code that implements it.
- **How `dromas-server` does it:** this repo.
- **A question about the protocol:** an issue in the client repo, where the open ones are.
- **A vulnerability:** privately, never in an issue: `SECURITY.md`.

## The certificate

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```
