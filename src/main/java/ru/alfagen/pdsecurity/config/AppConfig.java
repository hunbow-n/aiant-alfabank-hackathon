package ru.alfagen.pdsecurity.config;

import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ru.alfagen.pdsecurity.admission.ProcessingBudget;
import ru.alfagen.pdsecurity.detect.DefaultDetectionEngine;
import ru.alfagen.pdsecurity.detect.DetectionEngine;
import ru.alfagen.pdsecurity.detect.Detector;
import ru.alfagen.pdsecurity.detect.rules.AddressDetector;
import ru.alfagen.pdsecurity.detect.rules.BirthDateDetector;
import ru.alfagen.pdsecurity.detect.rules.BirthPlaceDetector;
import ru.alfagen.pdsecurity.detect.rules.CardDetector;
import ru.alfagen.pdsecurity.detect.rules.CardholderDetector;
import ru.alfagen.pdsecurity.detect.rules.CitizenshipDetector;
import ru.alfagen.pdsecurity.detect.rules.CvvDetector;
import ru.alfagen.pdsecurity.detect.rules.DateWordsDetector;
import ru.alfagen.pdsecurity.detect.rules.DepartmentCodeDetector;
import ru.alfagen.pdsecurity.detect.rules.DriverLicenseDetector;
import ru.alfagen.pdsecurity.detect.rules.EmailDetector;
import ru.alfagen.pdsecurity.detect.rules.InnDetector;
import ru.alfagen.pdsecurity.detect.rules.PassportDetector;
import ru.alfagen.pdsecurity.detect.rules.PassportIssueDateDetector;
import ru.alfagen.pdsecurity.detect.rules.PassportIssuerDetector;
import ru.alfagen.pdsecurity.detect.rules.PersonDetector;
import ru.alfagen.pdsecurity.detect.rules.PhoneDetector;
import ru.alfagen.pdsecurity.detect.rules.PinDetector;
import ru.alfagen.pdsecurity.detect.rules.SnilsDetector;
import ru.alfagen.pdsecurity.demo.LlmClient;
import ru.alfagen.pdsecurity.demo.MockLlmClient;
import ru.alfagen.pdsecurity.observability.ProcessingMetrics;
import ru.alfagen.pdsecurity.observability.TokenCounter;
import ru.alfagen.pdsecurity.policy.ComboEvaluator;
import ru.alfagen.pdsecurity.policy.PolicyProperties;
import ru.alfagen.pdsecurity.policy.PolicyRegistry;
import ru.alfagen.pdsecurity.resolve.GreedySpanResolver;
import ru.alfagen.pdsecurity.resolve.SpanResolver;
import ru.alfagen.pdsecurity.security.SystemAuthentication;
import ru.alfagen.pdsecurity.service.ConsumerService;
import ru.alfagen.pdsecurity.service.DetectionPipeline;
import ru.alfagen.pdsecurity.service.ProcessService;
import ru.alfagen.pdsecurity.service.SessionSupport;
import ru.alfagen.pdsecurity.session.Fingerprint;
import ru.alfagen.pdsecurity.session.InMemorySessionStore;
import ru.alfagen.pdsecurity.session.SessionCipher;
import ru.alfagen.pdsecurity.session.SessionStore;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Wires the application beans. All dependencies are injected via constructors.
 */
@Configuration
@EnableConfigurationProperties(PolicyProperties.class)
public class AppConfig {

    @Bean
    public Fingerprint fingerprint() {
        return new Fingerprint();
    }

    @Bean
    public SessionCipher sessionCipher() {
        return new SessionCipher();
    }

    @Bean
    public SessionStore sessionStore(Fingerprint fingerprint, PolicyProperties props) {
        return new InMemorySessionStore(
                200_000,
                Duration.ofMinutes(15),
                Duration.ofMinutes(5),
                fingerprint,
                Instant::now);
    }

    @Bean
    public ProcessingMetrics processingMetrics(MeterRegistry registry) {
        return new ProcessingMetrics(registry);
    }

    @Bean
    public TokenCounter tokenCounter() {
        return new TokenCounter();
    }

    @Bean
    public List<Detector> detectors() {
        return List.of(
                new PersonDetector(),
                new BirthDateDetector(),
                new DateWordsDetector(),
                new BirthPlaceDetector(),
                new PassportDetector(),
                new CitizenshipDetector(),
                new PassportIssuerDetector(),
                new DepartmentCodeDetector(),
                new PassportIssueDateDetector(),
                new DriverLicenseDetector(),
                new AddressDetector(),
                new EmailDetector(),
                new PhoneDetector(),
                new InnDetector(),
                new CardDetector(),
                new CvvDetector(),
                new PinDetector(),
                new CardholderDetector(),
                new SnilsDetector());
    }

    @Bean
    public DetectionEngine detectionEngine(List<Detector> detectors, ProcessingMetrics metrics) {
        return new DefaultDetectionEngine(detectors, metrics);
    }

    @Bean
    public SpanResolver spanResolver() {
        return new GreedySpanResolver();
    }

    @Bean
    public ComboEvaluator comboEvaluator() {
        return new ComboEvaluator();
    }

    @Bean
    public PolicyRegistry policyRegistry(PolicyProperties props) {
        return new PolicyRegistry(props);
    }

    @Bean
    public ProcessingBudget processingBudget() {
        return new ProcessingBudget(Runtime.getRuntime().availableProcessors());
    }

    @Bean
    public ProcessService processService(SessionStore store, SessionCipher cipher, Fingerprint fingerprint,
                                         DetectionEngine engine, SpanResolver resolver, ComboEvaluator combo,
                                         PolicyRegistry policies, ProcessingMetrics metrics, TokenCounter counter) {
        return new ProcessService(new SessionSupport(store, cipher, fingerprint),
                new DetectionPipeline(engine, resolver, combo, policies), metrics, counter);
    }

    @Bean
    public SystemAuthentication systemAuthentication() {
        java.util.Map<String, String> hashes = new java.util.HashMap<>();
        String crm = System.getenv("CRM_API_KEY_HASH");
        if (crm != null && !crm.isBlank()) {
            hashes.put("crm-bot", crm);
        }
        return new SystemAuthentication(hashes);
    }

    @Bean
    public ConsumerService consumerService(SessionStore store, SessionCipher cipher, Fingerprint fingerprint,
                                           DetectionEngine engine, SpanResolver resolver, ComboEvaluator combo,
                                           PolicyRegistry policies, ProcessingMetrics metrics, TokenCounter counter) {
        return new ConsumerService(new SessionSupport(store, cipher, fingerprint),
                new DetectionPipeline(engine, resolver, combo, policies), metrics, counter);
    }

    @Bean
    public LlmClient llmClient() {
        return new MockLlmClient();
    }
}