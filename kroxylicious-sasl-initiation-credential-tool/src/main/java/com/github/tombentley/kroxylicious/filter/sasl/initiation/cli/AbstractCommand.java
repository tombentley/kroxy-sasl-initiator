/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.util.concurrent.Callable;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials.KeyStoreCredentialStoreException;

import edu.umd.cs.findbugs.annotations.Nullable;
import picocli.CommandLine;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Spec;

/**
 * Base class for the credential tool commands.
 * <p>
 * The command turns known failures into a concise message on standard error and a non-zero exit code. Unexpected
 * runtime failures deliberately report only the exception type, never its message, so that an unforeseen exception
 * cannot echo secret material into the CLI output.
 * </p>
 */
abstract class AbstractCommand implements Callable<Integer> {

    @Spec
    private CommandSpec spec;

    @Override
    public final Integer call() {
        try {
            return execute();
        }
        catch (UsageException e) {
            err().println("Error: " + e.getMessage());
            return CommandLine.ExitCode.USAGE;
        }
        catch (CliException | KeyStoreCredentialStoreException e) {
            err().println("Error: " + e.getMessage());
            return CommandLine.ExitCode.SOFTWARE;
        }
        catch (IOException e) {
            err().println("Error: I/O failure: " + e.getMessage());
            return CommandLine.ExitCode.SOFTWARE;
        }
        catch (GeneralSecurityException e) {
            err().println("Error: KeyStore operation failed: " + e.getClass().getSimpleName());
            return CommandLine.ExitCode.SOFTWARE;
        }
        catch (RuntimeException e) {
            err().println("Error: Unexpected failure: " + e.getClass().getSimpleName());
            return CommandLine.ExitCode.SOFTWARE;
        }
        catch (Exception e) {
            err().println("Error: Unexpected failure: " + e.getClass().getSimpleName());
            return CommandLine.ExitCode.SOFTWARE;
        }
    }

    /**
     * Runs the command.
     *
     * @return the picocli exit code
     * @throws Exception on an expected failure
     */
    protected abstract int execute() throws IOException, GeneralSecurityException;

    protected final PrintWriter out() {
        return spec.commandLine().getOut();
    }

    protected final PrintWriter err() {
        return spec.commandLine().getErr();
    }

    protected static void requireNonBlank(@Nullable String value, String option) {
        if (value == null || value.isBlank()) {
            throw new UsageException(option + " must not be blank");
        }
    }
}
