package ru.alfagen.pdsecurity;

import org.junit.jupiter.api.Test;
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
import ru.alfagen.pdsecurity.observability.ProcessingMetrics;
import ru.alfagen.pdsecurity.policy.ComboEvaluator;
import ru.alfagen.pdsecurity.policy.PolicyProperties;
import ru.alfagen.pdsecurity.policy.PolicyRegistry;
import ru.alfagen.pdsecurity.resolve.GreedySpanResolver;
import ru.alfagen.pdsecurity.service.ProcessService;
import ru.alfagen.pdsecurity.session.Fingerprint;
import ru.alfagen.pdsecurity.session.InMemorySessionStore;
import ru.alfagen.pdsecurity.session.SessionCipher;
import ru.alfagen.pdsecurity.session.SessionStore;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * End-to-end round-trip over the /process state machine: original -> mask,
 * retry original -> same mask, mask -> original, retry mask -> original.
 */
class ProcessRoundTripTest {

    private ProcessService service;

    private ProcessService newService() {
        Fingerprint fp = new Fingerprint();
        SessionStore store = new InMemorySessionStore(1000, Duration.ofMinutes(15), Duration.ofMinutes(5), fp, java.time.Instant::now);
        SessionCipher cipher = new SessionCipher();
        List<Detector> detectors = List.of(
                new PersonDetector(), new BirthDateDetector(), new BirthPlaceDetector(),
                new PassportDetector(), new CitizenshipDetector(), new PassportIssuerDetector(),
                new DepartmentCodeDetector(), new PassportIssueDateDetector(), new DriverLicenseDetector(),
                new AddressDetector(), new EmailDetector(), new PhoneDetector(), new InnDetector(),
                new CardDetector(), new CvvDetector(), new PinDetector(), new CardholderDetector());
        ProcessingMetrics metrics = new ProcessingMetrics(new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
        DetectionEngine engine = new DefaultDetectionEngine(detectors, metrics);
        PolicyProperties props = new PolicyProperties();
        PolicyRegistry policies = new PolicyRegistry(props);
        return new ProcessService(store, cipher, fp, engine, new GreedySpanResolver(),
                new ComboEvaluator(), policies, metrics, new ru.alfagen.pdsecurity.observability.TokenCounter());
    }

    @Test
    void roundTrip() {
        service = newService();
        String original = "Клиент Иванов Иван Иванович, email ivan@example.com, телефон +7 912 345-67-89";
        String id = "id-1";

        ProcessService.ProcessResult mask = service.process(original, id);
        assertEquals(ProcessService.Operation.MASK, mask.operation());
        assertNotEquals(original, mask.result());

        ProcessService.ProcessResult retry = service.process(original, id);
        assertEquals(ProcessService.Operation.MASK_RETRY, retry.operation());
        assertEquals(mask.result(), retry.result());

        ProcessService.ProcessResult demask = service.process(mask.result(), id);
        assertEquals(ProcessService.Operation.DEMASK, demask.operation());
        assertEquals(original, demask.result());

        ProcessService.ProcessResult demaskRetry = service.process(mask.result(), id);
        assertEquals(ProcessService.Operation.DEMASK, demaskRetry.operation());
        assertEquals(original, demaskRetry.result());
    }

    @Test
    void noPiiReturnsTextVerbatim() {
        service = newService();
        String text = "Сегодня хорошая погода для прогулки.";
        ProcessService.ProcessResult r = service.process(text, "id-clean");
        assertEquals(text, r.result());
    }

    @Test
    void emptyPayloadAllowed() {
        service = newService();
        ProcessService.ProcessResult r = service.process("", "id-empty");
        assertEquals("", r.result());
    }
}