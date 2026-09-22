package ru.alfagen.pdsecurity;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * HTTP contract tests for /process: strict types, empty/whitespace payload,
 * malformed JSON, UTF-8 round-trip, and the mask/unmask flow.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ContractTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void maskThenUnmask() throws Exception {
        String body = "{\"payload\":\"Клиент Иванов Иван, email ivan@example.com\",\"payload_id\":\"c1\"}";
        String masked = mvc.perform(post("/process").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").isString())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        String result = extractResult(masked);

        String unmaskBody = "{\"payload\":" + jsonString(result) + ",\"payload_id\":\"c1\"}";
        mvc.perform(post("/process").contentType(MediaType.APPLICATION_JSON).content(unmaskBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value("Клиент Иванов Иван, email ivan@example.com"));
    }

    @Test
    void missingPayloadIdIs400() throws Exception {
        mvc.perform(post("/process").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"payload\":\"text\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void malformedJsonIs400() throws Exception {
        mvc.perform(post("/process").contentType(MediaType.APPLICATION_JSON)
                        .content("{not json"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void emptyPayloadAllowed() throws Exception {
        mvc.perform(post("/process").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"payload\":\"\",\"payload_id\":\"e1\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void conflictOnDifferentPayload() throws Exception {
        mvc.perform(post("/process").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"payload\":\"первый\",\"payload_id\":\"x1\"}"))
                .andExpect(status().isOk());
        mvc.perform(post("/process").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"payload\":\"второй\",\"payload_id\":\"x1\"}"))
                .andExpect(status().isConflict());
    }

    @Test
    void utf8RoundTrip() throws Exception {
        String original = "Эмодзи 😀 и кавычки \" и слэш \\ и таб\t";
        String body = "{\"payload\":" + jsonString(original) + ",\"payload_id\":\"u1\"}";
        String masked = mvc.perform(post("/process").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        String result = extractResult(masked);
        String unmaskBody = "{\"payload\":" + jsonString(result) + ",\"payload_id\":\"u1\"}";
        mvc.perform(post("/process").contentType(MediaType.APPLICATION_JSON).content(unmaskBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value(original));
    }

    private String extractResult(String responseBody) throws Exception {
        return new tools.jackson.databind.ObjectMapper()
                .readTree(responseBody).get("result").asText();
    }

    private String jsonString(String value) throws Exception {
        return new tools.jackson.databind.ObjectMapper().writeValueAsString(value);
    }
}