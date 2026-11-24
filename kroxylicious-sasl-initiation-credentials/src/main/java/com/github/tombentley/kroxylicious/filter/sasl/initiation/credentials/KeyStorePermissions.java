/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Checks that credential files are not accessible to group or other users on POSIX file systems.
 * <p>
 * The check is a no-op on non-POSIX file systems, where this information is unavailable. On POSIX systems, the file
 * must have no group or other permissions. A typical owner-only mode is {@code 0600} for regular files.
 * </p>
 * <p>
 * <strong>Kubernetes/OpenShift escape hatch:</strong> the kubelet may mount Secret volume files with
 * group-readable permissions that cannot be changed by the workload. Deployments that accept this platform behaviour
 * can set the environment variable
 * {@value #ALLOW_INSECURE_PERMISSIONS_ENV_VAR} to {@code true}. When set, permission checks are skipped and a warning
 * is logged. Use this only where the platform controls access to the mounted volume; do not use it to relax
 * permissions on ordinary host files.
 * </p>
 */
public final class KeyStorePermissions {

    /**
     * Environment variable that disables the POSIX owner-only permission check when set to {@code true}. See the class
     * documentation for the Kubernetes/OpenShift rationale.
     */
    public static final String ALLOW_INSECURE_PERMISSIONS_ENV_VAR = "KROXYLICIOUS_SASL_INITIATION_ALLOW_INSECURE_PERMISSIONS";

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStorePermissions.class);

    private static final Set<PosixFilePermission> INSECURE_PERMISSIONS = EnumSet.of(
            PosixFilePermission.GROUP_READ,
            PosixFilePermission.GROUP_WRITE,
            PosixFilePermission.GROUP_EXECUTE,
            PosixFilePermission.OTHERS_READ,
            PosixFilePermission.OTHERS_WRITE,
            PosixFilePermission.OTHERS_EXECUTE);

    private static final Set<PosixFilePermission> OWNER_ONLY = EnumSet.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE);

    private KeyStorePermissions() {
    }

    /**
     * Creates a regular file with owner-only ({@code rw-------}) permissions where the file system supports POSIX
     * permissions. This fails if the file already exists. On non-POSIX file systems the file is created with the
     * platform defaults.
     *
     * @param path the file to create
     * @return the created file
     * @throws IOException if the file cannot be created
     */
    public static Path createOwnerOnly(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        if (supportsPosix(path.getFileSystem())) {
            return Files.createFile(path, PosixFilePermissions.asFileAttribute(OWNER_ONLY));
        }
        return Files.createFile(path);
    }

    /**
     * Creates a temporary file with owner-only ({@code rw-------}) permissions where the file system supports POSIX
     * permissions. On non-POSIX file systems the file is created with the platform defaults.
     *
     * @param directory the directory in which to create the file
     * @param prefix the file name prefix
     * @param suffix the file name suffix
     * @return the created temporary file
     * @throws IOException if the file cannot be created
     */
    public static Path createTempFileOwnerOnly(Path directory, String prefix, String suffix) throws IOException {
        Objects.requireNonNull(directory, "directory");
        Objects.requireNonNull(prefix, "prefix");
        Objects.requireNonNull(suffix, "suffix");
        if (supportsPosix(directory.getFileSystem())) {
            return Files.createTempFile(directory, prefix, suffix, PosixFilePermissions.asFileAttribute(OWNER_ONLY));
        }
        return Files.createTempFile(directory, prefix, suffix);
    }

    /**
     * Sets owner-only ({@code rw-------}) permissions on an existing file where the file system supports POSIX
     * permissions. This is a no-op on non-POSIX file systems.
     *
     * @param path the file whose permissions should be restricted
     * @throws IOException if the permissions cannot be changed
     */
    public static void setOwnerOnly(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        PosixFileAttributeView posixView = Files.getFileAttributeView(path, PosixFileAttributeView.class);
        if (posixView != null) {
            posixView.setPermissions(OWNER_ONLY);
        }
    }

    private static boolean supportsPosix(FileSystem fileSystem) {
        return fileSystem.supportedFileAttributeViews().contains("posix");
    }

    /**
     * Checks the permissions of a credential-related file, honouring the documented escape hatch.
     *
     * @param path the file to check
     * @throws KeyStoreCredentialStoreException if the file is group- or other-accessible on a POSIX file system
     */
    public static void check(Path path) {
        check(path, System.getenv(ALLOW_INSECURE_PERMISSIONS_ENV_VAR));
    }

    /**
     * Checks the permissions of a credential-related file with an explicitly supplied escape-hatch value. This overload
     * exists so the escape hatch can be exercised in-process by tests and tooling; production code should use
     * {@link #check(Path)}.
     *
     * @param path the file to check
     * @param allowInsecureValue the value to treat as the escape-hatch setting
     * @throws KeyStoreCredentialStoreException if the file is group- or other-accessible on a POSIX file system
     */
    static void check(Path path, String allowInsecureValue) {
        Objects.requireNonNull(path, "path");
        if (isAllowInsecure(allowInsecureValue)) {
            LOGGER.atWarn()
                    .addKeyValue("envVar", ALLOW_INSECURE_PERMISSIONS_ENV_VAR)
                    .log("Insecure credential file permissions are explicitly allowed; owner-only permission checks are disabled");
            return;
        }
        if (!Files.exists(path)) {
            return;
        }
        PosixFileAttributeView posixView = Files.getFileAttributeView(path, PosixFileAttributeView.class);
        if (posixView == null) {
            return;
        }
        try {
            Set<PosixFilePermission> permissions = posixView.readAttributes().permissions();
            Set<PosixFilePermission> found = EnumSet.copyOf(INSECURE_PERMISSIONS);
            found.retainAll(permissions);
            if (!found.isEmpty()) {
                throw new KeyStoreCredentialStoreException(
                        "Credential file " + path + " has insecure permissions " + PosixFilePermissions.toString(permissions)
                                + "; group and other access are not allowed. Set owner-only permissions (for example, chmod 600)."
                                + " Deployments on Kubernetes/OpenShift that cannot change Secret volume permissions may set "
                                + ALLOW_INSECURE_PERMISSIONS_ENV_VAR + "=true.");
            }
        }
        catch (IOException e) {
            throw new KeyStoreCredentialStoreException("Failed to check permissions on credential file " + path, e);
        }
    }

    private static boolean isAllowInsecure(String value) {
        return value != null && "true".equalsIgnoreCase(value.trim());
    }
}
