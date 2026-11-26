/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package io.github.tombentley.kroxylicious.filter.sasl.initiation;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import io.github.tombentley.kroxylicious.filter.sasl.initiation.config.SaslInitiationConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Loads the documented example YAML files and validates every embedded {@code SaslInitiation}
 * configuration through the production configuration records.
 */
class ExampleConfigurationTest {

    private static final List<String> REQUIRED_EXAMPLES = List.of(
            "fixed-plain.yaml",
            "fixed-scram.yaml",
            "subject-scram.yaml",
            "oauth-fixed-token.yaml",
            "oauth-subject-client-credentials.yaml",
            "mtls-subject-scram.yaml",
            "routing-two-routes.yaml");

    private final ObjectMapper yaml = new ObjectMapper(new YAMLFactory());

    @Test
    void examplesContainValidSaslInitiationConfigurations() throws IOException {
        Path examplesDirectory = examplesDirectory();
        final List<Path> exampleFiles;
        try (var paths = Files.list(examplesDirectory)) {
            exampleFiles = paths
                    .filter(path -> path.getFileName().toString().endsWith(".yaml"))
                    .sorted()
                    .toList();
        }

        assertThat(exampleFiles)
                .extracting(path -> path.getFileName().toString())
                .containsAll(REQUIRED_EXAMPLES);

        int validatedConfigurations = 0;
        for (Path exampleFile : exampleFiles) {
            JsonNode root = yaml.readTree(Files.readString(exampleFile));
            JsonNode filterDefinitions = root.path("filterDefinitions");
            assertThat(filterDefinitions.isArray())
                    .as("filterDefinitions must be an array in %s", exampleFile.getFileName())
                    .isTrue();

            for (JsonNode filterDefinition : filterDefinitions) {
                String type = filterDefinition.path("type").asText();
                if (!type.equals("SaslInitiation") && !type.equals(SaslInitiation.class.getName())) {
                    continue;
                }
                JsonNode config = filterDefinition.get("config");
                assertThat(config)
                        .as("SaslInitiation must have a config in %s", exampleFile.getFileName())
                        .isNotNull();
                SaslInitiationConfig parsed = yaml.treeToValue(config, SaslInitiationConfig.class);
                assertThat(parsed.mechanism())
                        .as("parsed mechanism in %s", exampleFile.getFileName())
                        .isNotNull();
                assertThat(parsed.identity())
                        .as("parsed identity in %s", exampleFile.getFileName())
                        .isNotNull();
                validatedConfigurations++;
            }
        }

        // Routing has two initiators; the other examples have one each.
        assertThat(validatedConfigurations).isGreaterThanOrEqualTo(8);
    }

    private static Path examplesDirectory() {
        Path current = Path.of("").toAbsolutePath();
        while (current != null) {
            Path candidate = current.resolve("docs").resolve("examples");
            if (Files.isDirectory(candidate)) {
                return candidate;
            }
            current = current.getParent();
        }
        throw new IllegalStateException("Could not find docs/examples from " + Path.of("").toAbsolutePath());
    }
}
