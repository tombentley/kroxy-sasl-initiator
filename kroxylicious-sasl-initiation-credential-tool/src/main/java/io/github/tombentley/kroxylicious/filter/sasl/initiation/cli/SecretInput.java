/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Reads secrets from an interactive console, a file or standard input.
 * <p>
 * Interactive reads use {@link Console#readPassword(String, Object...)} and therefore do not echo. File and standard
 * input reads use the first line only and remove the line terminator; no other whitespace is trimmed. Callers own the
 * returned array and must zero it when finished.
 * </p>
 */
final class SecretInput {

    private SecretInput() {
    }

    static char[] read(String label,
                       String fileOption,
                       @Nullable Path file,
                       String stdinOption,
                       boolean stdin,
                       String argumentOption,
                       @Nullable String argument,
                       boolean allowArgument,
                       String consolePrompt) {
        Objects.requireNonNull(label, "label");
        validate(fileOption, file, stdinOption, stdin, argumentOption, argument, allowArgument);
        if (argument != null) {
            if (argument.isEmpty()) {
                throw new CliException("The " + label + " must not be empty");
            }
            return argument.toCharArray();
        }
        if (file != null) {
            return readFirstLineFromFile(label, file);
        }
        if (stdin) {
            return readFirstLineFromStdin(label);
        }
        return readFromConsole(label, consolePrompt);
    }

    static void validate(String fileOption,
                         @Nullable Path file,
                         String stdinOption,
                         boolean stdin,
                         String argumentOption,
                         @Nullable String argument,
                         boolean allowArgument) {
        int sources = (file == null ? 0 : 1) + (stdin ? 1 : 0) + (argument == null ? 0 : 1);
        if (sources > 1) {
            throw new UsageException("Specify at most one of " + fileOption + ", " + stdinOption + " or " + argumentOption);
        }
        if (argument != null && !allowArgument) {
            throw new UsageException(argumentOption + " requires --insecure-allow-password-argument; "
                    + "command-line arguments are visible in process listings and may be kept in shell history");
        }
    }

    private static char[] readFirstLineFromFile(String label, Path file) {
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            return requireFirstLine(label, reader);
        }
        catch (IOException e) {
            throw new CliException("Failed to read the " + label + " from " + file, e);
        }
    }

    private static char[] readFirstLineFromStdin(String label) {
        // Read one byte at a time so that a later stdin read (for example for the entry secret after a stdin store
        // password) sees the next line. A BufferedReader would read ahead and consume it.
        try {
            ByteArrayOutputStream line = new ByteArrayOutputStream();
            boolean readAny = false;
            int next;
            while ((next = System.in.read()) != -1) {
                readAny = true;
                if (next == '\n') {
                    break;
                }
                line.write(next);
            }
            if (!readAny && line.size() == 0) {
                throw new CliException("The " + label + " must not be empty");
            }
            byte[] bytes = line.toByteArray();
            int length = bytes.length;
            if (length > 0 && bytes[length - 1] == '\r') {
                length--;
            }
            String text = new String(bytes, 0, length, StandardCharsets.UTF_8);
            if (text.isEmpty()) {
                throw new CliException("The " + label + " must not be empty");
            }
            return text.toCharArray();
        }
        catch (IOException e) {
            throw new CliException("Failed to read the " + label + " from standard input", e);
        }
    }

    private static char[] requireFirstLine(String label, BufferedReader reader) throws IOException {
        String line = reader.readLine();
        if (line == null || line.isEmpty()) {
            throw new CliException("The " + label + " must not be empty");
        }
        return line.toCharArray();
    }

    private static char[] readFromConsole(String label, String prompt) {
        Console console = System.console();
        if (console == null) {
            throw new CliException("No interactive console is available for the " + label
                    + "; use --store-password-file/--store-password-stdin or --password-file/--password-stdin");
        }
        char[] secret = console.readPassword("%s", prompt);
        if (secret == null || secret.length == 0) {
            throw new CliException("The " + label + " must not be empty");
        }
        return secret;
    }
}
