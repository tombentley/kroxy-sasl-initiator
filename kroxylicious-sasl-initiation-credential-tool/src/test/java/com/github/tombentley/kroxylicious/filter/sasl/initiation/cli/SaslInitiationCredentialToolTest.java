/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.CredentialKind;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.DestroyableSecret;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreCredentialStore;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStorePermissions;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.OAuthClientCredential;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.PasswordCredential;
import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.SubjectAlias;

import picocli.CommandLine;

import static org.assertj.core.api.Assertions.assertThat;

class SaslInitiationCredentialToolTest {

    private static final String STORE_PASSWORD = "store-password-4e3f-do-not-log";
    private static final String ENTITY_PASSWORD = "entry-password-9a1c-do-not-log";
    private static final String NEW_ENTITY_PASSWORD = "new-entry-password-7b2d-do-not-log";
    private static final String CLIENT_SECRET = "client-secret-1f8e-do-not-log";
    private static final String NEW_CLIENT_SECRET = "new-client-secret-6c4a-do-not-log";
    private static final String WRONG_STORE_PASSWORD = "wrong-store-password-0d5b-do-not-log";

    @TempDir
    Path tempDir;

    private Path storePasswordFile;

    @Test
    void createCreatesAnEmptyOwnerOnlyPkcs12StoreAndRefusesToOverwrite() throws Exception {
        Path store = store();
        Path passwordFile = storePasswordFile();

        Result created = run("create", "--file", store.toString(), "--store-password-file", passwordFile.toString());

        assertThat(created.exitCode()).isZero();
        assertThat(created.stdout()).contains("Created credential store");
        assertNoSecrets(created);
        assertThat(store).isRegularFile();
        assertThat(Files.readAllBytes(store)[0]).isEqualTo((byte) 0x30);
        assertEmptyStore(store);
        assertOwnerOnly(store);

        Result again = run("create", "--file", store.toString(), "--store-password-file", passwordFile.toString());

        assertThat(again.exitCode()).isEqualTo(CommandLine.ExitCode.SOFTWARE);
        assertThat(again.stderr()).contains("already exists");
        assertNoSecrets(again);
    }

    @Test
    void addPasswordRoundTripsThroughKeyStoreCredentialStoreAndListRedactsSecrets() throws Exception {
        Path store = createStore();
        Path passwordFile = secretFile("entry.password", ENTITY_PASSWORD);

        Result added = run("add-password",
                "--file", store.toString(),
                "--subject", "alice",
                "--username", "broker-alice",
                "--store-password-file", storePasswordFile.toString(),
                "--password-file", passwordFile.toString());

        assertThat(added.exitCode()).isZero();
        assertThat(added.stdout()).contains("PASSWORD", "alice");
        assertNoSecrets(added);

        try (KeyStoreCredentialStore credentialStore = loadPasswordStore(store)) {
            PasswordCredential credential = (PasswordCredential) credentialStore.require("alice");
            assertThat(credential.username()).isEqualTo("broker-alice");
            assertSecret(credential.password(), ENTITY_PASSWORD);
        }
        assertThat(storeContainsAlias(store, SubjectAlias.hash("alice"))).isTrue();
        assertOwnerOnly(store);

        Result listed = run("list", "--file", store.toString(), "--store-password-file", storePasswordFile.toString());

        assertThat(listed.exitCode()).isZero();
        assertThat(listed.stdout()).contains("subject=alice type=PASSWORD username=broker-alice");
        assertThat(listed.stdout()).doesNotContain(SubjectAlias.hash("alice"));
        assertNoSecrets(listed);
    }

    @Test
    void addOAuthRoundTripsAndDefaultsExpectedSubjectToTheSubject() throws Exception {
        Path store = createStore();
        Path firstSecret = secretFile("client-one.secret", CLIENT_SECRET);
        Path secondSecret = secretFile("client-two.secret", "second-client-secret");

        Result first = run("add-oauth",
                "--file", store.toString(),
                "--subject", "alice",
                "--client-id", "alice-client",
                "--store-password-file", storePasswordFile.toString(),
                "--password-file", firstSecret.toString());
        Result second = run("add-oauth",
                "--file", store.toString(),
                "--subject", "bob",
                "--client-id", "bob-client",
                "--expected-subject", "broker-bob",
                "--store-password-file", storePasswordFile.toString(),
                "--client-secret-file", secondSecret.toString());

        assertThat(first.exitCode()).isZero();
        assertThat(second.exitCode()).isZero();
        assertNoSecrets(first);
        assertNoSecrets(second);

        try (KeyStoreCredentialStore credentialStore = loadOAuthStore(store)) {
            OAuthClientCredential alice = (OAuthClientCredential) credentialStore.require("alice");
            assertThat(alice.clientId()).isEqualTo("alice-client");
            assertThat(alice.expectedSubject()).isEqualTo("alice");
            assertSecret(alice.clientSecret(), CLIENT_SECRET);

            OAuthClientCredential bob = (OAuthClientCredential) credentialStore.require("bob");
            assertThat(bob.clientId()).isEqualTo("bob-client");
            assertThat(bob.expectedSubject()).isEqualTo("broker-bob");
            assertSecret(bob.clientSecret(), "second-client-secret");
        }

        Result listed = run("list", "--file", store.toString(), "--store-password-file", storePasswordFile.toString());

        assertThat(listed.exitCode()).isZero();
        assertThat(listed.stdout()).contains("subject=alice type=OAUTH expectedSubject=alice",
                "subject=bob type=OAUTH expectedSubject=broker-bob");
        assertNoSecrets(listed);
    }

    @Test
    void duplicateAddFailsAndUpdatePasswordReplacesTheExistingEntry() throws Exception {
        Path store = createStore();
        Path passwordFile = secretFile("entry.password", ENTITY_PASSWORD);
        Path newPasswordFile = secretFile("entry.new-password", NEW_ENTITY_PASSWORD);
        addPassword(store, "alice", "broker-alice", passwordFile);

        Result duplicate = run("add-password",
                "--file", store.toString(),
                "--subject", "alice",
                "--username", "broker-alice-2",
                "--store-password-file", storePasswordFile.toString(),
                "--password-file", newPasswordFile.toString());

        assertThat(duplicate.exitCode()).isEqualTo(CommandLine.ExitCode.SOFTWARE);
        assertThat(duplicate.stderr()).contains("already exists");
        assertNoSecrets(duplicate);
        try (KeyStoreCredentialStore credentialStore = loadPasswordStore(store)) {
            PasswordCredential credential = (PasswordCredential) credentialStore.require("alice");
            assertThat(credential.username()).isEqualTo("broker-alice");
            assertSecret(credential.password(), ENTITY_PASSWORD);
        }

        Result updated = run("update-password",
                "--file", store.toString(),
                "--subject", "alice",
                "--username", "broker-alice-2",
                "--store-password-file", storePasswordFile.toString(),
                "--password-file", newPasswordFile.toString());

        assertThat(updated.exitCode()).isZero();
        assertThat(updated.stdout()).contains("Updated PASSWORD");
        assertNoSecrets(updated);
        try (KeyStoreCredentialStore credentialStore = loadPasswordStore(store)) {
            PasswordCredential credential = (PasswordCredential) credentialStore.require("alice");
            assertThat(credential.username()).isEqualTo("broker-alice-2");
            assertSecret(credential.password(), NEW_ENTITY_PASSWORD);
        }

        Result missing = run("update-password",
                "--file", store.toString(),
                "--subject", "nobody",
                "--username", "broker-nobody",
                "--store-password-file", storePasswordFile.toString(),
                "--password-file", newPasswordFile.toString());

        assertThat(missing.exitCode()).isEqualTo(CommandLine.ExitCode.SOFTWARE);
        assertThat(missing.stderr()).contains("No credential exists for subject 'nobody'");
        assertNoSecrets(missing);
    }

    @Test
    void updateOAuthReplacesTheExistingEntryAndFailsForMissingSubject() throws Exception {
        Path store = createStore();
        Path firstSecret = secretFile("client-one.secret", CLIENT_SECRET);
        Path newSecret = secretFile("client-one.new-secret", NEW_CLIENT_SECRET);
        addOAuth(store, "alice", "alice-client", "alice", firstSecret);

        Result updated = run("update-oauth",
                "--file", store.toString(),
                "--subject", "alice",
                "--client-id", "alice-client-2",
                "--expected-subject", "broker-alice",
                "--store-password-file", storePasswordFile.toString(),
                "--password-file", newSecret.toString());

        assertThat(updated.exitCode()).isZero();
        assertNoSecrets(updated);
        try (KeyStoreCredentialStore credentialStore = loadOAuthStore(store)) {
            OAuthClientCredential credential = (OAuthClientCredential) credentialStore.require("alice");
            assertThat(credential.clientId()).isEqualTo("alice-client-2");
            assertThat(credential.expectedSubject()).isEqualTo("broker-alice");
            assertSecret(credential.clientSecret(), NEW_CLIENT_SECRET);
        }

        Result missing = run("update-oauth",
                "--file", store.toString(),
                "--subject", "nobody",
                "--client-id", "nobody-client",
                "--store-password-file", storePasswordFile.toString(),
                "--password-file", newSecret.toString());

        assertThat(missing.exitCode()).isEqualTo(CommandLine.ExitCode.SOFTWARE);
        assertThat(missing.stderr()).contains("No credential exists for subject 'nobody'");
        assertNoSecrets(missing);
    }

    @Test
    void removeDeletesTheEntryAndFailsForMissingSubjects() throws Exception {
        Path store = createStore();
        Path passwordFile = secretFile("entry.password", ENTITY_PASSWORD);
        addPassword(store, "alice", "broker-alice", passwordFile);
        addPassword(store, "bob", "broker-bob", passwordFile);

        Result removed = run("remove",
                "--file", store.toString(),
                "--subject", "alice",
                "--store-password-file", storePasswordFile.toString());

        assertThat(removed.exitCode()).isZero();
        assertThat(removed.stdout()).contains("Removed");
        assertNoSecrets(removed);
        try (KeyStoreCredentialStore credentialStore = loadPasswordStore(store)) {
            assertThat(credentialStore.credentials()).containsOnlyKeys("bob");
        }

        Result again = run("remove",
                "--file", store.toString(),
                "--subject", "alice",
                "--store-password-file", storePasswordFile.toString());

        assertThat(again.exitCode()).isEqualTo(CommandLine.ExitCode.SOFTWARE);
        assertThat(again.stderr()).contains("No credential exists for subject 'alice'");
        assertNoSecrets(again);
    }

    @Test
    void removeCanEmptyTheStore() throws Exception {
        Path store = createStore();
        Path passwordFile = secretFile("entry.password", ENTITY_PASSWORD);
        addPassword(store, "alice", "broker-alice", passwordFile);

        Result removed = run("remove",
                "--file", store.toString(),
                "--subject", "alice",
                "--store-password-file", storePasswordFile.toString());

        assertThat(removed.exitCode()).isZero();
        assertEmptyStore(store);
        assertOwnerOnly(store);
    }

    @Test
    void readsStorePasswordAndEntrySecretFromStdinFirstLineOnly() throws Exception {
        Path store = store();
        Result created = runWithStdin(STORE_PASSWORD + "\nignored-second-line\n",
                "create", "--file", store.toString(), "--store-password-stdin");
        assertThat(created.exitCode()).isZero();
        assertNoSecrets(created);

        Result added = runWithStdin("  spaced secret  \nignored-second-line\n",
                "add-password",
                "--file", store.toString(),
                "--subject", "alice",
                "--username", "broker-alice",
                "--store-password-file", storePasswordFile().toString(),
                "--password-stdin");

        assertThat(added.exitCode()).isZero();
        assertNoSecrets(added);
        try (KeyStoreCredentialStore credentialStore = loadPasswordStore(store)) {
            PasswordCredential credential = (PasswordCredential) credentialStore.require("alice");
            assertSecret(credential.password(), "  spaced secret  ");
        }
    }

    @Test
    void readsBothStdinSecretsFromConsecutiveLines() throws Exception {
        Path store = createStore();

        Result added = runWithStdin(STORE_PASSWORD + "\r\n" + ENTITY_PASSWORD + "\r\n",
                "add-password",
                "--file", store.toString(),
                "--subject", "alice",
                "--username", "broker-alice",
                "--store-password-stdin",
                "--password-stdin");

        assertThat(added.exitCode()).isZero();
        assertNoSecrets(added);
        try (KeyStoreCredentialStore credentialStore = loadPasswordStore(store)) {
            PasswordCredential credential = (PasswordCredential) credentialStore.require("alice");
            assertThat(credential.username()).isEqualTo("broker-alice");
            assertSecret(credential.password(), ENTITY_PASSWORD);
        }
    }

    @Test
    void inlineSecretsRequireTheExplicitInsecureGate() throws Exception {
        Path store = store();

        Result storePasswordWithoutGate = run("create",
                "--file", store.toString(),
                "--store-password", STORE_PASSWORD);

        assertThat(storePasswordWithoutGate.exitCode()).isEqualTo(CommandLine.ExitCode.USAGE);
        assertThat(storePasswordWithoutGate.stderr()).contains("--insecure-allow-password-argument");
        assertNoSecrets(storePasswordWithoutGate);
        assertThat(store).doesNotExist();

        Result storePasswordWithGate = run("create",
                "--file", store.toString(),
                "--store-password", STORE_PASSWORD,
                "--insecure-allow-password-argument");
        assertThat(storePasswordWithGate.exitCode()).isZero();
        assertNoSecrets(storePasswordWithGate);

        Path passwordFile = secretFile("entry.password", ENTITY_PASSWORD);
        Result entryPasswordWithoutGate = run("add-password",
                "--file", store.toString(),
                "--subject", "alice",
                "--username", "broker-alice",
                "--store-password-file", storePasswordFile().toString(),
                "--password", ENTITY_PASSWORD);

        assertThat(entryPasswordWithoutGate.exitCode()).isEqualTo(CommandLine.ExitCode.USAGE);
        assertThat(entryPasswordWithoutGate.stderr()).contains("--insecure-allow-password-argument");
        assertNoSecrets(entryPasswordWithoutGate);

        Result entryPasswordWithGate = run("add-password",
                "--file", store.toString(),
                "--subject", "alice",
                "--username", "broker-alice",
                "--store-password-file", storePasswordFile().toString(),
                "--password", ENTITY_PASSWORD,
                "--insecure-allow-password-argument");

        assertThat(entryPasswordWithGate.exitCode()).isZero();
        assertNoSecrets(entryPasswordWithGate);
        try (KeyStoreCredentialStore credentialStore = loadPasswordStore(store)) {
            PasswordCredential credential = (PasswordCredential) credentialStore.require("alice");
            assertSecret(credential.password(), ENTITY_PASSWORD);
        }
        assertThat(passwordFile).isRegularFile();
    }

    @Test
    void missingFileFailsForEveryCommandThatNeedsAnExistingStore() throws Exception {
        Path missing = tempDir.resolve("missing.p12");
        Path passwordFile = secretFile("entry.password", ENTITY_PASSWORD);

        Result listed = run("list", "--file", missing.toString(), "--store-password-file", storePasswordFile().toString());
        Result added = run("add-password",
                "--file", missing.toString(),
                "--subject", "alice",
                "--username", "broker-alice",
                "--store-password-file", storePasswordFile().toString(),
                "--password-file", passwordFile.toString());
        Result removed = run("remove",
                "--file", missing.toString(),
                "--subject", "alice",
                "--store-password-file", storePasswordFile().toString());

        assertThat(listed.exitCode()).isEqualTo(CommandLine.ExitCode.SOFTWARE);
        assertThat(added.exitCode()).isEqualTo(CommandLine.ExitCode.SOFTWARE);
        assertThat(removed.exitCode()).isEqualTo(CommandLine.ExitCode.SOFTWARE);
        assertThat(listed.stderr()).contains("not found");
        assertThat(added.stderr()).contains("not found");
        assertThat(removed.stderr()).contains("not found");
        assertNoSecrets(listed);
        assertNoSecrets(added);
        assertNoSecrets(removed);
    }

    @Test
    void wrongStorePasswordFailsWithoutLeakingEitherPassword() throws Exception {
        Path store = createStore();
        Path wrongPasswordFile = secretFile("wrong-store.password", WRONG_STORE_PASSWORD);
        Path passwordFile = secretFile("entry.password", ENTITY_PASSWORD);

        Result listed = run("list", "--file", store.toString(), "--store-password-file", wrongPasswordFile.toString());
        Result added = run("add-password",
                "--file", store.toString(),
                "--subject", "alice",
                "--username", "broker-alice",
                "--store-password-file", wrongPasswordFile.toString(),
                "--password-file", passwordFile.toString());

        assertThat(listed.exitCode()).isEqualTo(CommandLine.ExitCode.SOFTWARE);
        assertThat(added.exitCode()).isEqualTo(CommandLine.ExitCode.SOFTWARE);
        assertThat(listed.stderr()).contains("password may be incorrect");
        assertThat(added.stderr()).contains("password may be incorrect");
        assertNoSecrets(listed, WRONG_STORE_PASSWORD);
        assertNoSecrets(added, WRONG_STORE_PASSWORD);
    }

    @Test
    void malformedStoreFailsCleanly() throws Exception {
        Path store = tempDir.resolve("not-a-keystore.p12");
        Files.writeString(store, "this is not a keystore", StandardCharsets.UTF_8);
        KeyStorePermissions.setOwnerOnly(store);

        Result listed = run("list", "--file", store.toString(), "--store-password-file", storePasswordFile().toString());

        assertThat(listed.exitCode()).isEqualTo(CommandLine.ExitCode.SOFTWARE);
        assertThat(listed.stderr()).contains("not a PKCS12 file");
        assertNoSecrets(listed);

        Path pseudoPkcs12 = tempDir.resolve("corrupt.p12");
        Files.write(pseudoPkcs12, new byte[]{ 0x30, 0x03, 0x01, 0x02 });
        KeyStorePermissions.setOwnerOnly(pseudoPkcs12);

        Result corrupt = run("list", "--file", pseudoPkcs12.toString(), "--store-password-file", storePasswordFile().toString());

        assertThat(corrupt.exitCode()).isEqualTo(CommandLine.ExitCode.SOFTWARE);
        assertThat(corrupt.stderr()).contains("Failed to load the credential store");
        assertNoSecrets(corrupt);
    }

    @Test
    void missingSubjectOptionIsAUsageError() {
        Path store = tempDir.resolve("never-created.p12");

        Result result = run("add-password",
                "--file", store.toString(),
                "--username", "broker-alice",
                "--store-password", STORE_PASSWORD,
                "--password", ENTITY_PASSWORD);

        assertThat(result.exitCode()).isEqualTo(CommandLine.ExitCode.USAGE);
        assertThat(result.stderr()).contains("--subject");
        assertNoSecrets(result);
    }

    @Test
    @EnabledOnOs({ OS.LINUX, OS.MAC })
    void rejectsStoreFilesWithInsecurePermissions() throws Exception {
        Path store = createStore();
        Files.setPosixFilePermissions(store, PosixFilePermissions.fromString("rw-r--r--"));

        Result listed = run("list", "--file", store.toString(), "--store-password-file", storePasswordFile.toString());

        assertThat(listed.exitCode()).isEqualTo(CommandLine.ExitCode.SOFTWARE);
        assertThat(listed.stderr()).contains("insecure permissions");
        assertNoSecrets(listed);
    }

    @Test
    void listOfAnEmptyStoreSucceedsAndPrintsNoSecrets() throws Exception {
        Path store = createStore();

        Result listed = run("list", "--file", store.toString(), "--store-password-file", storePasswordFile.toString());

        assertThat(listed.exitCode()).isZero();
        assertThat(listed.stdout()).isEmpty();
        assertNoSecrets(listed);
    }

    @Test
    void helpDocumentsTheInsecureGateAndContainsNoSecrets() {
        Result result = run("--help");

        assertThat(result.exitCode()).isZero();
        assertThat(result.stdout()).contains("--insecure-allow-password-argument");
        assertThat(result.stdout()).contains("create", "add-password", "add-oauth", "update-password", "update-oauth", "remove", "list");
        assertNoSecrets(result);
    }

    private Path store() {
        return tempDir.resolve("credentials.p12");
    }

    private Path storePasswordFile() throws IOException {
        if (storePasswordFile == null) {
            storePasswordFile = secretFile("store.password", STORE_PASSWORD);
        }
        return storePasswordFile;
    }

    private Path createStore() throws IOException {
        Path store = store();
        Result result = run("create", "--file", store.toString(), "--store-password-file", storePasswordFile().toString());
        assertThat(result.exitCode()).isZero();
        return store;
    }

    private Path secretFile(String name, String content) throws IOException {
        Path file = tempDir.resolve(name);
        Files.writeString(file, content + "\n", StandardCharsets.UTF_8);
        KeyStorePermissions.setOwnerOnly(file);
        return file;
    }

    private void addPassword(Path store, String subject, String username, Path passwordFile) throws IOException {
        Result result = run("add-password",
                "--file", store.toString(),
                "--subject", subject,
                "--username", username,
                "--store-password-file", storePasswordFile().toString(),
                "--password-file", passwordFile.toString());
        assertThat(result.exitCode()).isZero();
    }

    private void addOAuth(Path store, String subject, String clientId, String expectedSubject, Path secretFile) throws IOException {
        Result result = run("add-oauth",
                "--file", store.toString(),
                "--subject", subject,
                "--client-id", clientId,
                "--expected-subject", expectedSubject,
                "--store-password-file", storePasswordFile().toString(),
                "--password-file", secretFile.toString());
        assertThat(result.exitCode()).isZero();
    }

    private static KeyStoreCredentialStore loadPasswordStore(Path store) {
        return KeyStoreCredentialStore.load(store, () -> STORE_PASSWORD, CredentialKind.PASSWORD);
    }

    private static KeyStoreCredentialStore loadOAuthStore(Path store) {
        return KeyStoreCredentialStore.load(store, () -> STORE_PASSWORD, CredentialKind.OAUTH);
    }

    private static void assertSecret(DestroyableSecret secret, String expected) {
        char[] chars = secret.chars();
        try {
            assertThat(chars).containsExactly(expected.toCharArray());
        }
        finally {
            Arrays.fill(chars, '\0');
        }
    }

    private static void assertEmptyStore(Path store) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] password = STORE_PASSWORD.toCharArray();
        try (InputStream input = Files.newInputStream(store)) {
            keyStore.load(input, password);
        }
        finally {
            Arrays.fill(password, '\0');
        }
        assertThat(keyStore.size()).isZero();
    }

    private static boolean storeContainsAlias(Path store, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] password = STORE_PASSWORD.toCharArray();
        try (InputStream input = Files.newInputStream(store)) {
            keyStore.load(input, password);
        }
        finally {
            Arrays.fill(password, '\0');
        }
        return keyStore.containsAlias(alias);
    }

    private static void assertOwnerOnly(Path file) throws IOException {
        if (Files.getFileAttributeView(file, java.nio.file.attribute.PosixFileAttributeView.class) != null) {
            assertThat(Files.getPosixFilePermissions(file)).isEqualTo(PosixFilePermissions.fromString("rw-------"));
        }
    }

    private static void assertNoSecrets(Result result, String... extraSecrets) {
        String output = result.combined();
        assertThat(output).doesNotContain(STORE_PASSWORD, ENTITY_PASSWORD, NEW_ENTITY_PASSWORD,
                CLIENT_SECRET, NEW_CLIENT_SECRET, WRONG_STORE_PASSWORD);
        assertThat(output).doesNotContain(SubjectAlias.hash("alice"), SubjectAlias.hash("bob"));
        for (String extraSecret : extraSecrets) {
            assertThat(output).doesNotContain(extraSecret);
        }
    }

    private Result run(String... args) {
        CommandLine commandLine = new CommandLine(new SaslInitiationCredentialTool());
        StringWriter stdout = new StringWriter();
        StringWriter stderr = new StringWriter();
        commandLine.setOut(new PrintWriter(stdout));
        commandLine.setErr(new PrintWriter(stderr));
        int exitCode = commandLine.execute(args);
        return new Result(exitCode, stdout.toString(), stderr.toString());
    }

    private Result runWithStdin(String stdin, String... args) {
        InputStream original = System.in;
        try {
            System.setIn(new ByteArrayInputStream(stdin.getBytes(StandardCharsets.UTF_8)));
            return run(args);
        }
        finally {
            System.setIn(original);
        }
    }

    private record Result(int exitCode, String stdout, String stderr) {

        String combined() {
            return stdout + stderr;
        }
    }
}
