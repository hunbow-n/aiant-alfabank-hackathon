package ru.alfagen.pdsecurity.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Request body for {@code POST /process}. {@code payload} may be empty or
 * whitespace-only; {@code payload_id} must be non-blank. Extra JSON fields are
 * ignored by Jackson.
 */
public record ProcessRequest(
        @NotNull @JsonProperty("payload") String payload,
        @NotBlank @JsonProperty("payload_id") String payloadId) {
}