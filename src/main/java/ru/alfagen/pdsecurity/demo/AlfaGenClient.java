package ru.alfagen.pdsecurity.demo;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.Map;

/**
 * Calls the AlfaGen gateway with an OpenAI-compatible chat completion request.
 * Used only by the demo page: the evaluated {@code /process} endpoint never
 * talks to a model.
 *
 * <p>The prompt instructs the model to copy placeholders verbatim, which is
 * what makes restoration possible afterwards.
 */
public final class AlfaGenClient implements LlmClient {

    private static final String CA_BUNDLE = "/certs/russian-trusted-ca.pem";

    private static final String SYSTEM_PROMPT = """
            Ты помощник банковского оператора. В тексте встречаются плейсхолдеры
            вида {{TYPE_1}} — это скрытые персональные данные. Копируй их в ответ
            дословно, не расшифровывай, не изменяй и не спрашивай, что они значат.
            Всегда отвечай содержательным текстом для клиента на русском языке и
            упоминай в нём подходящие плейсхолдеры. Если явной задачи нет,
            составь короткое вежливое подтверждение о приёме данных в работу.
            Не переспрашивай и не проси уточнений.""";

    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();
    private final String baseUrl;
    private final String apiKey;
    private final String model;
    private final Duration timeout;

    public AlfaGenClient(String baseUrl, String apiKey, String model, Duration timeout) {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
        this.model = model;
        this.timeout = timeout;
        this.http = buildClient();
    }

    /**
     * The gateway is signed by the Russian Trusted CA, which is absent from the
     * default JDK trust store. The bundled root and intermediate certificates
     * are the only ones trusted for this call, so the connection stays verified
     * instead of being silently disabled.
     */
    private static HttpClient buildClient() {
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5));
        try (InputStream pem = AlfaGenClient.class.getResourceAsStream(CA_BUNDLE)) {
            if (pem == null) {
                return builder.build();
            }
            KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
            trust.load(null, null);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            int index = 0;
            for (Certificate certificate : factory.generateCertificates(pem)) {
                trust.setCertificateEntry("russian-trusted-" + index++, certificate);
            }
            TrustManagerFactory trustManagers =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trust);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trustManagers.getTrustManagers(), null);
            return builder.sslContext(context).build();
        } catch (IOException | GeneralSecurityException e) {
            return builder.build();
        }
    }

    /**
     * Собирает текст из SSE-потока: строки вида {@code data: {...}} с фрагментами
     * ответа и завершающая {@code data: [DONE]}.
     */
    private String collect(String stream) {
        StringBuilder text = new StringBuilder();
        for (String line : stream.split("\n")) {
            String trimmed = line.strip();
            if (!trimmed.startsWith("data:")) {
                continue;
            }
            String payload = trimmed.substring(5).strip();
            if (payload.isEmpty() || "[DONE]".equals(payload)) {
                continue;
            }
            JsonNode chunk = mapper.readTree(payload);
            JsonNode delta = chunk.path("choices").path(0).path("delta").path("content");
            if (!delta.isMissingNode() && !delta.isNull()) {
                text.append(delta.asText());
            }
        }
        if (text.isEmpty()) {
            throw new IllegalStateException("AlfaGen returned an empty stream");
        }
        return text.toString();
    }

    public boolean configured() {
        return apiKey != null && !apiKey.isBlank();
    }

    @Override
    public String complete(String prompt) {
        if (!configured()) {
            throw new IllegalStateException("AlfaGen API key is not configured");
        }
        try {
            String body = mapper.writeValueAsString(Map.of(
                    "model", model,
                    "temperature", 0.2,
                    // Шлюз принимает только потоковый режим: обычный ответ отклоняется с 400.
                    "stream", true,
                    "messages", java.util.List.of(
                            Map.of("role", "system", "content", SYSTEM_PROMPT),
                            Map.of("role", "user", "content", prompt))));
            HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/chat/completions"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + apiKey)
                    .timeout(timeout)
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("AlfaGen responded with " + response.statusCode());
            }
            return collect(response.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("AlfaGen call interrupted", e);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("AlfaGen call failed", e);
        }
    }
}
