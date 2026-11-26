/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.IVersionProvider;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Spec;

/**
 * Command line tool for creating and maintaining the PKCS12 credential store used by SASL initiation.
 * <p>
 * Secrets are read interactively without echo, from a file, or from standard input. Passing a secret as a
 * command-line argument is possible only with the explicit {@code --insecure-allow-password-argument} gate. The tool
 * never prints passwords, client secrets, aliases or raw entry bytes.
 * </p>
 */
@Command(name = "sasl-initiation-credential-tool", mixinStandardHelpOptions = true, versionProvider = SaslInitiationCredentialTool.VersionProvider.class, description = "Create and maintain the PKCS12 credential store used by the Kroxylicious SASL initiation filter.", footer = {
        "",
        "Secrets are read from an interactive console (without echo), from a file or from standard input.",
        "Use --insecure-allow-password-argument only to permit secret values on the command line; this is",
        "unsafe because arguments can appear in process listings and shell history."
}, subcommands = {
        CreateCommand.class,
        AddPasswordCommand.class,
        AddOAuthCommand.class,
        UpdatePasswordCommand.class,
        UpdateOAuthCommand.class,
        RemoveCommand.class,
        ListCommand.class
})
public final class SaslInitiationCredentialTool implements Runnable {

    @Spec
    private CommandSpec spec;

    @Override
    public void run() {
        spec.commandLine().usage(spec.commandLine().getOut());
    }

    /**
     * Runs the CLI and terminates the JVM with the command's exit code.
     *
     * @param args command-line arguments
     */
    public static void main(String[] args) {
        System.exit(new CommandLine(new SaslInitiationCredentialTool()).execute(args));
    }

    /**
     * Supplies the version shown by {@code --version}.
     */
    static final class VersionProvider implements IVersionProvider {

        @Override
        public String[] getVersion() {
            String version = SaslInitiationCredentialTool.class.getPackage().getImplementationVersion();
            return new String[]{ "sasl-initiation-credential-tool " + (version == null ? "(development)" : version) };
        }
    }
}
