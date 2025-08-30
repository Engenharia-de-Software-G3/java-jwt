package com.auth0.jwt.impl;

import com.auth0.jwt.RegisteredClaims;
import com.fasterxml.jackson.core.JsonGenerator;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Jackson serializer implementation for converting into JWT Payload parts.
 * <p>
 * This class is thread-safe.
 *
 * @see com.auth0.jwt.JWTCreator
 */
public class PayloadSerializer extends ClaimsSerializer<PayloadClaimsHolder> {
    public PayloadSerializer() {
        super(PayloadClaimsHolder.class);
    }

    @Override
    protected void writeClaim(Map.Entry<String, Object> entry, JsonGenerator gen) throws IOException {
        if (RegisteredClaims.AUDIENCE.equals(entry.getKey())) {
            writeAudience(gen, entry);
        } else {
            super.writeClaim(entry, gen);
        }
    }

    /**
     * Audience may be a list of strings or a single string. This is needed to properly handle the aud claim when
     * added with the {@linkplain com.auth0.jwt.JWTCreator.Builder#withPayload(Map)} method.
     */
    private void writeAudience(JsonGenerator gen, Map.Entry<String, Object> e) throws IOException {
        Object value = e.getValue();
        if (value == null) {
            return;
        }

        if (value instanceof String) {
            gen.writeFieldName(e.getKey());
            gen.writeString((String) value);
            return;
        }

        List<String> aud = extractAudienceStrings(value);

        if (aud.isEmpty()) {
            return;
        }

        gen.writeFieldName(e.getKey());
        if (aud.size() == 1) {
            gen.writeString(aud.get(0));
            return;
        }

        gen.writeStartArray();
        for (String s : aud) {
            gen.writeString(s);
        }
        gen.writeEndArray();
    }

    private List<String> extractAudienceStrings(Object value) {
        if (value instanceof String[]) {
            return Arrays.stream((String[]) value)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());
        }

        if (value instanceof Iterable<?>) {
            return StreamSupport.stream(((Iterable<?>) value).spliterator(), false)
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .collect(Collectors.toList());
        }
        return Collections.emptyList();
    }
}
