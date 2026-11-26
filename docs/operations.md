# KeyStore and CLI operations

## Credential store format

The filter uses a dedicated PKCS12 file. It is not the SCRAM credential store used by
`SaslTermination`, and it cannot be shared with it.

* Store type: PKCS12.
* One `SecretKeyEntry` per identity.
* Alias: lowercase hexadecimal SHA-256 of the UTF-8 lookup key (`subject`).
* Entry payload: UTF-8 JSON with a required `version` field.
* The same password protects the store and its entries.
* The store is loaded once during filter initialization.

The JSON is deliberately strict. Unknown fields, duplicate JSON keys, a version other than `1`,
missing or empty fields, a non-secret entry, an alias that does not match the subject, a duplicate
subject and an empty store all fail startup.

### Password entry (PLAIN/SCRAM)

```json
{
  "version": 1,
  "subject": "alice",
  "username": "svc-alice",
  "password": "the broker password"
}
```

* `subject` is the lookup key and must match the alias.
* `username` is the broker authentication ID. It may equal `subject` or be a mapped service account.
* `password` is plaintext inside the encrypted KeyStore because PLAIN and SCRAM must present it.

### OAuth client-credential entry (OAUTHBEARER)

```json
{
  "version": 1,
  "subject": "alice",
  "oauthBearer": {
    "clientId": "alice-client",
    "clientSecret": "the OAuth client secret",
    "expectedSubject": "alice"
  }
}
```

`expectedSubject` is optional in the file; when omitted it defaults to `subject`. The retrieved
token's configured subject claim must equal it. An OAuth token file with a fixed identity does not
use a KeyStore entry.

Use the CLI rather than `keytool` or a text editor. Do not commit stores or password files to source
control.

## Building the CLI

The release distribution provides a `sasl-initiation-credential-tool` launcher. From a source
checkout, build the executable jar with:

```shell
mvn -pl kroxylicious-sasl-initiation-credential-tool -am package
```

The shaded jar is:

```text
kroxylicious-sasl-initiation-credential-tool/target/kroxylicious-sasl-initiation-credential-tool-0.1.0-SNAPSHOT-all.jar
```

The shaded jar deliberately does not contain Kroxylicious, Kafka, Jackson or SLF4J. The
distribution launcher supplies those runtime jars. To run from a source checkout without the
distribution, install the modules and build the runtime classpath:

```shell
mvn -q -DskipTests -DskipITs install
mvn -q -pl kroxylicious-sasl-initiation-credential-tool \
  dependency:build-classpath -Dmdep.outputFile=target/cli-classpath.txt
java -cp "kroxylicious-sasl-initiation-credential-tool/target/kroxylicious-sasl-initiation-credential-tool-0.1.0-SNAPSHOT-all.jar:$(cat kroxylicious-sasl-initiation-credential-tool/target/cli-classpath.txt)" \
  io.github.tombentley.kroxylicious.filter.sasl.initiation.cli.SaslInitiationCredentialTool --help
```

The rest of this page uses `sasl-initiation-credential-tool` as the launcher name.

## Commands

| Command | Purpose |
| --- | --- |
| `create --file <path>` | Create a new empty PKCS12 store. Fails if the file already exists. The parent directory must exist. |
| `add-password --file <path> --subject <s> --username <u>` | Add a password credential. Fails if the subject already exists. |
| `add-oauth --file <path> --subject <s> --client-id <id> [--expected-subject <s>]` | Add an OAuth client credential. `expectedSubject` defaults to the subject. Fails if the subject already exists. |
| `update-password --file <path> --subject <s> --username <u>` | Replace an existing password credential. Fails if the subject does not exist. |
| `update-oauth --file <path> --subject <s> --client-id <id> [--expected-subject <s>]` | Replace an existing OAuth credential. Fails if the subject does not exist. |
| `remove --file <path> --subject <s>` | Remove a credential. Fails if the subject does not exist. |
| `list --file <path>` | Print subject, credential type, and username or expected OAuth subject. Never prints passwords, client secrets, aliases or entry bytes. |

Use `--help` on the tool or any subcommand for the current option list.

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Operation failed (missing file, wrong password, duplicate/missing subject, malformed store, I/O failure). |
| `2` | Command-line usage error, including an insecure password argument without its gate. |

Errors never include secret values. Unexpected failures report only the exception type.

## Password and secret input

The CLI never accepts secrets on the command line by default.

### Store password

| Option | Behaviour |
| --- | --- |
| *(none)* | Read interactively from the console without echo. Requires a real console. |
| `--store-password-file <path>` | Read the first line of the file, removing the line ending only. Recommended for automation and Kubernetes. |
| `--store-password-stdin` | Read the first line of standard input. |
| `--store-password <value>` | Insecure. Requires `--insecure-allow-password-argument`. |

### Broker password / OAuth client secret

| Option | Behaviour |
| --- | --- |
| *(none)* | Read interactively from the console without echo. |
| `--password-file <path>` | Read the first line of the file, removing the line ending only. `--client-secret-file` is an alias. |
| `--password-stdin` | Read the first line of standard input. `--client-secret-stdin` is an alias. |
| `--password <value>` / `--client-secret <value>` | Insecure. Requires `--insecure-allow-password-argument`. |

Only one source may be supplied for each secret. File and stdin input use the first line only; the
line ending is removed, but other whitespace is preserved. Interactive input uses
`Console.readPassword` and does not echo.

Command-line arguments can appear in process listings, shell history, process accounting and logs.
Use the file, stdin or interactive form.

## Common workflows

### Create a store and add a shared identity

```shell
# Store password, owner-only file
printf '%s\n' "$STORE_PASSWORD" > /etc/kroxylicious/sasl-initiation.p12.password
chmod 600 /etc/kroxylicious/sasl-initiation.p12.password

sasl-initiation-credential-tool create \
  --file /etc/kroxylicious/sasl-initiation.p12 \
  --store-password-file /etc/kroxylicious/sasl-initiation.p12.password

# Entry password, owner-only file
printf '%s\n' "$BROKER_PASSWORD" > /etc/kroxylicious/broker-password
chmod 600 /etc/kroxylicious/broker-password

sasl-initiation-credential-tool add-password \
  --file /etc/kroxylicious/sasl-initiation.p12 \
  --subject proxy-service \
  --username svc-proxy \
  --store-password-file /etc/kroxylicious/sasl-initiation.p12.password \
  --password-file /etc/kroxylicious/broker-password
```

The YAML uses the lookup key, not the broker username:

```yaml
mechanism: SCRAM-SHA-256
identity:
  mode: fixed
  key: proxy-service
keyStore:
  file: /etc/kroxylicious/sasl-initiation.p12
  filePassword:
    passwordFile: /etc/kroxylicious/sasl-initiation.p12.password
```

### Add per-client identities for subject mode

Create one entry per downstream principal name. The entry can map to a different broker username:

```shell
sasl-initiation-credential-tool add-password \
  --file /etc/kroxylicious/sasl-initiation.p12 \
  --subject alice \
  --username svc-alice \
  --store-password-file /etc/kroxylicious/sasl-initiation.p12.password \
  --password-file /etc/kroxylicious/sasl-alice-password

sasl-initiation-credential-tool add-password \
  --file /etc/kroxylicious/sasl-initiation.p12 \
  --subject bob \
  --username svc-bob \
  --store-password-file /etc/kroxylicious/sasl-initiation.p12.password \
  --password-file /etc/kroxylicious/sasl-bob-password
```

### Add OAuth client credentials

```shell
sasl-initiation-credential-tool add-oauth \
  --file /etc/kroxylicious/sasl-initiation.p12 \
  --subject alice \
  --client-id alice-client \
  --expected-subject alice \
  --store-password-file /etc/kroxylicious/sasl-initiation.p12.password \
  --client-secret-file /etc/kroxylicious/alice-client.secret
```

For a fixed identity, use the configured `identity.key` as `--subject`.

### Update, remove and inspect

```shell
sasl-initiation-credential-tool update-password \
  --file /etc/kroxylicious/sasl-initiation.p12 \
  --subject alice \
  --username svc-alice \
  --store-password-file /etc/kroxylicious/sasl-initiation.p12.password \
  --password-file /etc/kroxylicious/alice-new-password

sasl-initiation-credential-tool list \
  --file /etc/kroxylicious/sasl-initiation.p12 \
  --store-password-file /etc/kroxylicious/sasl-initiation.p12.password

sasl-initiation-credential-tool remove \
  --file /etc/kroxylicious/sasl-initiation.p12 \
  --subject alice \
  --store-password-file /etc/kroxylicious/sasl-initiation.p12.password
```

`list` output is intentionally non-secret:

```text
subject=alice type=PASSWORD username=svc-alice
subject=bob type=OAUTH expectedSubject=bob
```

## File permissions

On POSIX file systems, the filter rejects a store or `passwordFile` that has any group or other
permission. The CLI enforces the same policy on the store file it opens. Owner-only mode is
required:

```shell
chmod 600 /etc/kroxylicious/sasl-initiation.p12
chmod 600 /etc/kroxylicious/sasl-initiation.p12.password
```

The CLI creates new stores and password-protected temporary files with owner-only (`rw-------`)
permissions and updates the store using an owner-only temporary file in the same directory followed
by an atomic replace where the file system supports it. The permission check is a no-op on
non-POSIX file systems.

### Kubernetes/OpenShift relaxation

Kubernetes Secret volumes are sometimes mounted group-readable (for example `0444` or `0644`), and
the workload may not be able to change the mode. Prefer telling Kubernetes to mount the files
owner-readable:

```yaml
volumes:
  - name: sasl-initiation-credentials
    secret:
      secretName: sasl-initiation-credentials
      defaultMode: 0400
```

If the platform still cannot satisfy the owner-only check, set the explicitly documented escape
hatch on the **proxy process**:

```yaml
env:
  - name: KROXYLICIOUS_SASL_INITIATION_ALLOW_INSECURE_PERMISSIONS
    value: "true"
```

When set to `true` (case-insensitive), the owner-only check is skipped and a warning is logged. Use
it only where the platform controls access to the mounted volume. Do not set it globally on a host
to relax ordinary files, and do not use it to avoid fixing permissions you can fix.

### Kubernetes Secret example

Create the store and password file on a trusted workstation, then create the Secret:

```shell
kubectl create secret generic sasl-initiation-credentials \
  --from-file=sasl-initiation.p12=/etc/kroxylicious/sasl-initiation.p12 \
  --from-file=sasl-initiation.p12.password=/etc/kroxylicious/sasl-initiation.p12.password
```

Mount it read-only and point `keyStore.file` and `keyStore.filePassword.passwordFile` at the mounted
paths. Restrict access to the Secret with RBAC. The password file is a secret too.

## Rotation

There is **no hot reload** in this release. The filter loads and validates the KeyStore once during
initialization, and the loaded credential objects are shared by the virtual cluster's filter
instances. Editing the file while the proxy is running does not change the credentials in use.

Rotation procedure:

1. Update the entry with `update-password` or `update-oauth` (or add/remove entries).
2. Update the corresponding broker-side credential so the new value is valid.
3. Restart every proxy instance that uses the store. A rolling restart is fine, but all replicas
   must eventually be restarted.
4. Confirm successful authentication in the proxy logs and metrics.

For a coordinated rotation, create a new store file, populate it with the new credentials, update the
proxy configuration to point at the new file and password file, then restart. The CLI's in-place
update is atomic at the file level, but a running proxy still has the old contents in memory until
restart.

To change the store password itself, create a new store with the new password, re-add the entries,
update the configured password file, and restart. There is no separate change-password command.

In Kubernetes, update the Secret, wait for the kubelet to refresh the mounted files (or mount the
Secret as a projected volume), then restart the pods. Do not rely on a Secret update alone to rotate
the live proxy credentials.

## Troubleshooting credential files

| Symptom | Likely cause and action |
| --- | --- |
| `Credential KeyStore file not found` | The configured path is not mounted or is misspelled. Check the path from inside the proxy container. |
| `not a PKCS12 file; PKCS12 is required` | The file is JKS, a text file, or truncated. Recreate it with the CLI. |
| `the file may not be a PKCS12 KeyStore or the password may be incorrect` | Wrong `filePassword`, or the store is corrupt. Verify the password file contents and first line. |
| `has insecure permissions` | Run `chmod 600` on the store and password file, or use the documented Kubernetes/OpenShift escape hatch. |
| `The credential KeyStore is empty` | Create at least one entry with `add-password` or `add-oauth`. |
| `No PASSWORD credential is configured for key ...` | Add the entry or correct `identity.key` / the subject principal name. |
| `... is OAUTH but the store was loaded expecting PASSWORD` | The store contains the wrong credential kind for the configured mechanism. Use a separate store per credential kind. |
| `KeyStore alias ... does not match the SHA-256 hash of its subject` | The file was edited or created by an incompatible tool. Rebuild it with the CLI. |
