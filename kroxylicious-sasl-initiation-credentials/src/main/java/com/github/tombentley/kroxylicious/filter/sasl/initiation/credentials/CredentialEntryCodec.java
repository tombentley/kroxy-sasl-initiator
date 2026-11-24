/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.credentials;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;

import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Encodes and decodes the version 1 KeyStore entry JSON.
 * <p>
 * Decoding is deliberately strict: the JSON must be a single object, duplicate keys are rejected, unknown fields at
 * either level are rejected, fields must have the correct JSON type, and the version must be exactly
 * {@value CredentialEntry#CURRENT_VERSION}. Validation messages name fields but never include field values that may be
 * secret.
 * </p>
 * <p>
 * The JSON text contains plaintext secrets by design; the PKCS12 store protects it at rest. Malformed-JSON errors are
 * deliberately sanitized because Jackson's own messages can include excerpts of the offending value. The Jackson
 * exception is not attached as a cause, so logging the resulting exception cannot leak the payload.
 * </p>
 */
public final class CredentialEntryCodec {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();

    private static final String VERSION = "version";
    private static final String SUBJECT = "subject";
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String OAUTH_BEARER = "oauthBearer";
    private static final String CLIENT_ID = "clientId";
    private static final String CLIENT_SECRET = "clientSecret";
    private static final String EXPECTED_SUBJECT = "expectedSubject";

    private static final Set<String> PASSWORD_FIELDS = Set.of(VERSION, SUBJECT, USERNAME, PASSWORD);
    private static final Set<String> OAUTH_FIELDS = Set.of(VERSION, SUBJECT, OAUTH_BEARER);
    private static final Set<String> OAUTH_BEARER_FIELDS = Set.of(CLIENT_ID, CLIENT_SECRET, EXPECTED_SUBJECT);

    private CredentialEntryCodec() {
    }

    /**
     * Decodes a credential entry from UTF-8 JSON bytes.
     *
     * @param json the JSON bytes
     * @return the decoded entry
     * @throws KeyStoreCredentialStoreException if the JSON is malformed or does not match the v1 schema
     */
    public static CredentialEntry decode(byte[] json) {
        Objects.requireNonNull(json, "json");
        final JsonNode root;
        try {
            root = OBJECT_MAPPER.readValue(json, JsonNode.class);
        }
        catch (IOException e) {
            throw malformed(e);
        }
        return decode(root);
    }

    /**
     * Decodes a credential entry from JSON text.
     *
     * @param json the JSON text
     * @return the decoded entry
     * @throws KeyStoreCredentialStoreException if the JSON is malformed or does not match the v1 schema
     */
    public static CredentialEntry decode(String json) {
        Objects.requireNonNull(json, "json");
        return decode(json.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Encodes a credential entry as UTF-8 JSON bytes suitable for storing in a PKCS12 {@code SecretKeyEntry}.
     *
     * @param entry the entry to encode
     * @return the JSON bytes
     * @throws KeyStoreCredentialStoreException if encoding fails
     */
    public static byte[] encode(CredentialEntry entry) {
        Objects.requireNonNull(entry, "entry");
        ObjectNode root = OBJECT_MAPPER.createObjectNode();
        root.put(VERSION, entry.version());
        root.put(SUBJECT, entry.subject());
        if (entry instanceof PasswordCredentialEntry passwordEntry) {
            root.put(USERNAME, passwordEntry.username());
            root.put(PASSWORD, passwordEntry.password());
        }
        else if (entry instanceof OAuthCredentialEntry oauthEntry) {
            ObjectNode oauthNode = root.putObject(OAUTH_BEARER);
            oauthNode.put(CLIENT_ID, oauthEntry.oauthBearer().clientId());
            oauthNode.put(CLIENT_SECRET, oauthEntry.oauthBearer().clientSecret());
            oauthNode.put(EXPECTED_SUBJECT, oauthEntry.oauthBearer().expectedSubject());
        }
        else {
            throw new IllegalStateException("Unsupported credential entry type: " + entry.getClass().getName());
        }
        try {
            return OBJECT_MAPPER.writeValueAsBytes(root);
        }
        catch (JsonProcessingException e) {
            throw new KeyStoreCredentialStoreException("Failed to encode the credential entry as JSON", e);
        }
    }

    private static CredentialEntry decode(@Nullable JsonNode root) {
        if (root == null || root.isNull() || !root.isObject()) {
            throw invalid("the JSON value must be an object");
        }

        boolean oauth = root.has(OAUTH_BEARER);
        Set<String> allowedFields = oauth ? OAUTH_FIELDS : PASSWORD_FIELDS;
        rejectUnknownFields(root, allowedFields, oauth ? "OAuth" : "password");

        int version = requireInt(root, VERSION);
        String subject = requireText(root, SUBJECT);

        try {
            if (oauth) {
                JsonNode oauthNode = root.get(OAUTH_BEARER);
                if (oauthNode == null || !oauthNode.isObject()) {
                    throw invalid("field '" + OAUTH_BEARER + "' must be an object");
                }
                rejectUnknownFields(oauthNode, OAUTH_BEARER_FIELDS, "OAuth bearer");
                String clientId = requireText(oauthNode, CLIENT_ID);
                String clientSecret = requireText(oauthNode, CLIENT_SECRET);
                String expectedSubject = oauthNode.has(EXPECTED_SUBJECT)
                        ? requireText(oauthNode, EXPECTED_SUBJECT)
                        : null;
                return new OAuthCredentialEntry(version, subject,
                        new OAuthCredentialEntry.OAuthBearer(clientId, clientSecret, expectedSubject));
            }
            String username = requireText(root, USERNAME);
            String password = requireText(root, PASSWORD);
            return new PasswordCredentialEntry(version, subject, username, password);
        }
        catch (IllegalArgumentException e) {
            throw invalid(e.getMessage());
        }
    }

    private static void rejectUnknownFields(JsonNode object, Set<String> allowedFields, String variant) {
        Iterator<String> fieldNames = object.fieldNames();
        while (fieldNames.hasNext()) {
            String fieldName = fieldNames.next();
            if (!allowedFields.contains(fieldName)) {
                throw invalid("unknown field '" + fieldName + "' in " + variant + " credential entry");
            }
        }
    }

    private static int requireInt(JsonNode object, String field) {
        JsonNode node = object.get(field);
        if (node == null || node.isNull()) {
            throw invalid("required field '" + field + "' is missing or null");
        }
        if (!node.isIntegralNumber()) {
            throw invalid("field '" + field + "' must be an integer");
        }
        if (!node.canConvertToInt()) {
            throw invalid("field '" + field + "' is out of range");
        }
        return node.intValue();
    }

    private static String requireText(JsonNode object, String field) {
        JsonNode node = object.get(field);
        if (node == null || node.isNull()) {
            throw invalid("required field '" + field + "' is missing or null");
        }
        if (!node.isTextual()) {
            throw invalid("field '" + field + "' must be a string");
        }
        String value = node.textValue();
        if (value.isEmpty()) {
            throw invalid("field '" + field + "' must not be empty");
        }
        return value;
    }

    private static KeyStoreCredentialStoreException invalid(String detail) {
        return new KeyStoreCredentialStoreException("Invalid credential entry: " + detail);
    }

    private static KeyStoreCredentialStoreException malformed(IOException exception) {
        String location = "";
        if (exception instanceof JsonProcessingException processingException) {
            JsonLocation jsonLocation = processingException.getLocation();
            if (jsonLocation != null && jsonLocation.getLineNr() > 0) {
                location = " at line " + jsonLocation.getLineNr() + ", column " + jsonLocation.getColumnNr();
            }
        }
        return new KeyStoreCredentialStoreException(
                "Malformed credential entry JSON" + location + "; expected a single JSON object matching schema version "
                        + CredentialEntry.CURRENT_VERSION);
    }
}
