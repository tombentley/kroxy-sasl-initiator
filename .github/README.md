# CI/CD and Maven Central setup

This repository publishes the parent POM, `kroxylicious-sasl-initiation-credentials`, the
`kroxylicious-sasl-initiation` filter plugin, and the `kroxylicious-sasl-initiation-credential-tool`
to Maven Central. The `kroxylicious-sasl-initiation-integration-tests` module is test-only and is
never deployed.

## One-time setup

1. Verify the namespace `io.github.tombentley` on the
   [Central Portal](https://central.sonatype.com/publishing/namespaces). This is the GitHub-backed
   namespace for the `tombentley` GitHub account and should verify automatically when signed in with
   GitHub. The project groupId is `io.github.tombentley.kroxylicious.sasl`, which is under that
   namespace.
2. Enable snapshot publishing for the namespace if you want the `Publish snapshot` workflow to
   deploy development builds.
3. Generate a Sonatype Central user token from your
   [Central Portal account](https://central.sonatype.com/account).
4. Generate a GPG key:
   ```shell
   gpg --full-generate-key
   gpg --armor --export-secret-keys <key-id>
   gpg --keyserver keyserver.ubuntu.com --send-keys <key-id>
   ```
   Central checks that the signing key is publicly resolvable, so the `--send-keys` step is
   required. Use a key that does not expire before you stop releasing, or plan to rotate the secret.
5. Add the repository secrets below under **Settings → Secrets and variables → Actions**.

   | Secret | Purpose |
   | --- | --- |
   | `CENTRAL_TOKEN_USERNAME` | Sonatype Central user token username |
   | `CENTRAL_TOKEN_PASSWORD` | Sonatype Central user token password |
   | `GPG_PRIVATE_KEY` | Armoured GPG private key used to sign release artifacts |
   | `GPG_PASSPHRASE` | Passphrase for `GPG_PRIVATE_KEY` |

6. If `main` is a protected branch, allow the release workflow to push to it (for example include
   `github-actions[bot]` in the branches that can push), or replace `github.token` in
   `release.yaml` with a PAT that has repository write access.

## Workflows

- **ci.yaml** — build, unit tests, integration tests, Checkstyle, formatting and SpotBugs on every
  push to `main` and every pull request. A separate job runs the Docker-backed OAUTHBEARER
  integration test.
- **publish-snapshot.yaml** — on every push to `main`, deploys the current `-SNAPSHOT` to the
  Central Portal snapshot repository. It is a no-op when the version is not a snapshot.
- **release.yaml** — manual: **Actions → Release → Run workflow**. It takes `release-version` and
  `next-version` inputs, then sets the release version, builds/signs/publishes it to Central, tags
  it, creates a GitHub release, sets the next `-SNAPSHOT` version, and pushes everything.
- **dco.yaml** — on every pull request, checks that every non-merge commit has a `Signed-off-by`
  trailer matching the commit author or committer. To make sign-off mandatory, add the
  **Check commit sign-offs** job as a required status check under **Settings → Branches** for
  `main`.

## Developer Certificate of Origin

Contributions must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/).
Create signed-off commits with `git commit --signoff`; to sign off an existing branch, run
`git rebase --signoff <base-branch>`. To sign off every commit automatically, set
`git config format.signOff true`. Dependabot commits are exempt.

## First release

1. Make sure the working tree is clean and `main` is up to date.
2. Run the **Release** workflow with, for example:
   - `release-version`: `0.1.0`
   - `next-version`: `0.2.0-SNAPSHOT`
   - `branch`: `main`
3. Wait for the Central Portal validation and publishing to finish. The workflow waits until the
   deployment is published before tagging the release.
4. Check that the artifacts appear under
   `io.github.tombentley.kroxylicious.sasl` on [Maven Central](https://central.sonatype.com/).

A release cannot be changed or deleted after it is published. If the workflow fails before the
deployment is published, fix the problem and rerun it; if it fails after publishing, do not reuse
the same version.
