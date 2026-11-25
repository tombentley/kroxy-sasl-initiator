/*
 * Copyright Kroxylicious Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */

package com.github.tombentley.kroxylicious.filter.sasl.initiation.it;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionStage;

import com.github.tombentley.kroxylicious.filter.sasl.initiation.it.CompositionObserverFilter.Config;

import io.kroxylicious.kafka.common.compress.Compression;
import io.kroxylicious.kafka.common.header.Header;
import io.kroxylicious.kafka.common.header.internals.RecordHeader;
import io.kroxylicious.kafka.common.message.ProduceRequestData;
import io.kroxylicious.kafka.common.message.RequestHeaderData;
import io.kroxylicious.kafka.common.message.SaslAuthenticateRequestData;
import io.kroxylicious.kafka.common.message.SaslHandshakeRequestData;
import io.kroxylicious.kafka.common.protocol.ApiKeys;
import io.kroxylicious.kafka.common.protocol.ApiMessage;
import io.kroxylicious.kafka.common.record.TimestampType;
import io.kroxylicious.kafka.common.record.internal.MemoryRecords;
import io.kroxylicious.kafka.common.record.internal.MemoryRecordsBuilder;
import io.kroxylicious.kafka.common.record.internal.Record;
import io.kroxylicious.kafka.common.record.internal.RecordBatch;
import io.kroxylicious.kafka.common.utils.ByteBufferOutputStream;
import io.kroxylicious.proxy.config.NamedFilterDefinition;
import io.kroxylicious.proxy.filter.Filter;
import io.kroxylicious.proxy.filter.FilterContext;
import io.kroxylicious.proxy.filter.FilterFactory;
import io.kroxylicious.proxy.filter.FilterFactoryContext;
import io.kroxylicious.proxy.filter.RequestFilter;
import io.kroxylicious.proxy.filter.RequestFilterResult;
import io.kroxylicious.proxy.plugin.Plugin;
import io.kroxylicious.proxy.plugin.PluginConfigurationException;
import io.kroxylicious.testing.integration.config.NamedFilterDefinitionBuilder;

/**
 * Test-only observer that records the SASL mechanism and authorization id used by {@code SaslInitiation} on the
 * upstream connection, and annotates produced records with that information plus the downstream subject visible at the
 * point the record is produced.
 * <p>
 * It is deliberately placed after {@code SaslInitiation}, closest to the broker, so it sees the initiator's own
 * {@code SaslHandshake}/{@code SaslAuthenticate} frames and proves that they reach the broker. It never terminates or
 * modifies SASL; it only parses the authorization id from the client-first message (PLAIN or SCRAM) and forwards the
 * frame unchanged.
 * </p>
 * <p>
 * <strong>This filter is for integration tests only. It must not be used in production.</strong>
 * </p>
 */
@Plugin(configType = Config.class)
public class CompositionObserverFilter implements FilterFactory<Config, Config> {

    /** Header containing the downstream subject observed after {@code SaslInitiation}. */
    public static final String DOWNSTREAM_SUBJECT_HEADER = "x-composition-downstream-subject";
    /** Header containing the mechanism used on the upstream connection. */
    public static final String UPSTREAM_MECHANISM_HEADER = "x-composition-upstream-mechanism";
    /** Header containing the authorization id used on the upstream connection. */
    public static final String UPSTREAM_AUTHORIZATION_ID_HEADER = "x-composition-upstream-authorization-id";

    /**
     * Empty configuration for the test observer.
     */
    public record Config() {}

    /**
     * Creates a named filter definition for this observer.
     *
     * @param name the filter definition name
     * @return the filter definition
     */
    public static NamedFilterDefinition definition(String name) {
        return new NamedFilterDefinitionBuilder(name, CompositionObserverFilter.class.getName())
                .withConfig(Map.of())
                .build();
    }

    /**
     * Default constructor used by the runtime.
     */
    public CompositionObserverFilter() {
        // Intentionally empty.
    }

    @Override
    public Config initialize(FilterFactoryContext context, Config config) throws PluginConfigurationException {
        return config;
    }

    @Override
    public Filter createFilter(FilterFactoryContext context, Config config) {
        return new ObservingFilter();
    }

    private static final class ObservingFilter implements RequestFilter {

        private String upstreamMechanism = "";
        private String upstreamAuthorizationId = "";

        @Override
        public CompletionStage<RequestFilterResult> onRequest(ApiKeys apiKey,
                                                              short apiVersion,
                                                              RequestHeaderData header,
                                                              ApiMessage request,
                                                              FilterContext context) {
            switch (apiKey) {
                case SASL_HANDSHAKE -> upstreamMechanism = ((SaslHandshakeRequestData) request).mechanism();
                case SASL_AUTHENTICATE -> {
                    String parsedAuthorizationId = authorizationId(upstreamMechanism,
                            ((SaslAuthenticateRequestData) request).authBytes());
                    if (!parsedAuthorizationId.isEmpty()) {
                        upstreamAuthorizationId = parsedAuthorizationId;
                    }
                }
                case PRODUCE -> injectHeaders((ProduceRequestData) request, context);
                default -> {
                    // Nothing to observe.
                }
            }
            return context.forwardRequest(header, request);
        }

        private void injectHeaders(ProduceRequestData request, FilterContext context) {
            List<RecordHeader> headers = List.of(
                    new RecordHeader(DOWNSTREAM_SUBJECT_HEADER,
                            context.authenticatedSubject().toString().getBytes(StandardCharsets.UTF_8)),
                    new RecordHeader(UPSTREAM_MECHANISM_HEADER, upstreamMechanism.getBytes(StandardCharsets.UTF_8)),
                    new RecordHeader(UPSTREAM_AUTHORIZATION_ID_HEADER, upstreamAuthorizationId.getBytes(StandardCharsets.UTF_8)));

            for (ProduceRequestData.TopicProduceData topicDatum : request.topicData()) {
                for (ProduceRequestData.PartitionProduceData partitionDatum : topicDatum.partitionData()) {
                    MemoryRecords records = (MemoryRecords) partitionDatum.records();
                    partitionDatum.setRecords(addHeaders(records, headers, context));
                }
            }
        }

        private static MemoryRecords addHeaders(MemoryRecords records, List<RecordHeader> headers, FilterContext context) {
            ByteBufferOutputStream output = context.createByteBufferOutputStream(records.sizeInBytes());
            for (RecordBatch batch : records.batches()) {
                Compression compression = Compression.of(batch.compressionType()).build();
                TimestampType timestampType = batch.timestampType() == TimestampType.NO_TIMESTAMP_TYPE
                        ? TimestampType.CREATE_TIME
                        : batch.timestampType();
                long logAppendTime = timestampType == TimestampType.LOG_APPEND_TIME ? batch.maxTimestamp() : RecordBatch.NO_TIMESTAMP;
                try (MemoryRecordsBuilder builder = new MemoryRecordsBuilder(output, batch.magic(), compression,
                        timestampType, batch.baseOffset(), logAppendTime, batch.producerId(), batch.producerEpoch(),
                        batch.baseSequence(), batch.isTransactional(), batch.isControlBatch(), batch.partitionLeaderEpoch(),
                        output.limit(), batch.deleteHorizonMs().orElse(RecordBatch.NO_TIMESTAMP))) {
                    for (Record record : batch) {
                        builder.appendWithOffset(record.offset(), record.timestamp(), record.key(), record.value(),
                                mergeHeaders(record.headers(), headers));
                    }
                    if (batch.magic() >= RecordBatch.MAGIC_VALUE_V2) {
                        // Preserve the last sequence number even when the batch was not originally full.
                        builder.overrideLastOffset(batch.lastOffset());
                    }
                }
            }
            ByteBuffer buffer = output.buffer().duplicate();
            buffer.flip();
            return MemoryRecords.readableRecords(buffer);
        }

        private static Header[] mergeHeaders(Header[] existing, List<RecordHeader> headers) {
            List<Header> result = new ArrayList<>(existing.length + headers.size());
            result.addAll(Arrays.asList(existing));
            result.addAll(headers);
            return result.toArray(new Header[0]);
        }

        private static String authorizationId(String mechanism, byte[] authBytes) {
            if (authBytes == null || authBytes.length == 0) {
                return "";
            }
            return switch (mechanism) {
                case "PLAIN" -> plainAuthorizationId(authBytes);
                case "SCRAM-SHA-256", "SCRAM-SHA-512" -> scramAuthorizationId(authBytes);
                default -> "";
            };
        }

        private static String plainAuthorizationId(byte[] authBytes) {
            String[] parts = new String(authBytes, StandardCharsets.UTF_8).split("\u0000", -1);
            return parts.length > 1 ? parts[1] : "";
        }

        private static String scramAuthorizationId(byte[] authBytes) {
            String message = new String(authBytes, StandardCharsets.UTF_8);
            int gs2HeaderEnd = message.indexOf(",,");
            String bareMessage = gs2HeaderEnd >= 0 ? message.substring(gs2HeaderEnd + 2) : message;
            for (String attribute : bareMessage.split(",", -1)) {
                if (attribute.startsWith("n=")) {
                    return decodeSaslName(attribute.substring(2));
                }
            }
            return "";
        }

        private static String decodeSaslName(String value) {
            return value.replace("=2C", ",").replace("=3D", "=");
        }
    }
}
