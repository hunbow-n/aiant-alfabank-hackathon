package ru.alfagen.pdsecurity.demo;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;

/**
 * Demo request: the text a reviewer pastes plus the settings they chose on the
 * page.
 *
 * @param text     source text with personal data
 * @param system   consumer system id whose policy is applied
 * @param strategy mask strategy override: star, token or synthetic
 * @param llm      which model to call: mock or alfagen
 */
public record DemoRunRequest(
        @NotNull String text,
        String system,
        String strategy,
        @JsonProperty("llm") String llmMode) {
}
