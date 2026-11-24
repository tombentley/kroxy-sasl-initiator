/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyStorePermissionsTest {

    @TempDir
    Path tempDir;

    @Test
    @EnabledOnOs({ OS.LINUX, OS.MAC })
    void createsAndRestrictsFilesToOwnerOnly() throws Exception {
        Path created = KeyStorePermissions.createOwnerOnly(tempDir.resolve("created.p12"));
        assertThat(Files.getPosixFilePermissions(created)).isEqualTo(PosixFilePermissions.fromString("rw-------"));

        Path written = tempDir.resolve("written.p12");
        Files.writeString(written, "material");
        Files.setPosixFilePermissions(written, PosixFilePermissions.fromString("rw-r--r--"));
        KeyStorePermissions.setOwnerOnly(written);
        assertThat(Files.getPosixFilePermissions(written)).isEqualTo(PosixFilePermissions.fromString("rw-------"));
    }

    @Test
    @EnabledOnOs({ OS.LINUX, OS.MAC })
    void acceptsOwnerOnlyPermissions() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        Files.writeString(file, "not a real keystore");
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));

        assertThatCode(() -> KeyStorePermissions.check(file)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = { "rw-r-----", "rw-r--r--", "rw-rw----", "rwxr-x---", "rw-------" })
    @EnabledOnOs({ OS.LINUX, OS.MAC })
    void rejectsGroupOrOtherAccess(String permissions) throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        Files.writeString(file, "not a real keystore");
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString(permissions));

        if ("rw-------".equals(permissions)) {
            assertThatCode(() -> KeyStorePermissions.check(file)).doesNotThrowAnyException();
        }
        else {
            assertThatThrownBy(() -> KeyStorePermissions.check(file))
                    .isInstanceOf(KeyStoreCredentialStoreException.class)
                    .hasMessageContaining("insecure permissions")
                    .hasMessageContaining(KeyStorePermissions.ALLOW_INSECURE_PERMISSIONS_ENV_VAR);
        }
    }

    @Test
    @EnabledOnOs({ OS.LINUX, OS.MAC })
    void escapeHatchAllowsInsecurePermissions() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        Files.writeString(file, "not a real keystore");
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"));

        assertThatCode(() -> KeyStorePermissions.check(file, "true")).doesNotThrowAnyException();
        assertThatCode(() -> KeyStorePermissions.check(file, "TRUE")).doesNotThrowAnyException();
        assertThatCode(() -> KeyStorePermissions.check(file, " true ")).doesNotThrowAnyException();
    }

    @Test
    @EnabledOnOs({ OS.LINUX, OS.MAC })
    void unrecognizedEscapeHatchValueKeepsStrictCheck() throws Exception {
        Path file = tempDir.resolve("credentials.p12");
        Files.writeString(file, "not a real keystore");
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"));

        assertThatThrownBy(() -> KeyStorePermissions.check(file, "yes"))
                .isInstanceOf(KeyStoreCredentialStoreException.class)
                .hasMessageContaining("insecure permissions");
    }

    @Test
    void missingPathIsIgnored() {
        Path missing = tempDir.resolve("missing.p12");

        assertThatCode(() -> KeyStorePermissions.check(missing)).doesNotThrowAnyException();
    }

    @Test
    void nonPosixFileSystemIsNoOp() throws Exception {
        Path zip = tempDir.resolve("test.zip");
        URI uri = URI.create("jar:" + zip.toUri());
        try (FileSystem fileSystem = FileSystems.newFileSystem(uri, Map.of("create", "true"))) {
            Path file = fileSystem.getPath("credentials.p12");
            Files.writeString(file, "not a real keystore");

            assertThatCode(() -> KeyStorePermissions.check(file)).doesNotThrowAnyException();
        }
    }
}
