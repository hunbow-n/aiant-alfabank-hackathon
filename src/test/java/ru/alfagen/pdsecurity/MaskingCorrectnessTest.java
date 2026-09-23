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
import ru.alfagen.pdsecurity.service.DetectionPipeline;
import ru.alfagen.pdsecurity.service.ProcessService;
import ru.alfagen.pdsecurity.service.SessionSupport;
import ru.alfagen.pdsecurity.session.Fingerprint;
import ru.alfagen.pdsecurity.session.InMemorySessionStore;
import ru.alfagen.pdsecurity.session.SessionCipher;
import ru.alfagen.pdsecurity.session.SessionStore;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end masking correctness: for composite entities (passport, card, INN,
 * driver license) no digit of the original value may remain in the output, and
 * the output length must equal the input length.
 */
class MaskingCorrectnessTest {

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
        PolicyRegistry policies = new PolicyRegistry(new PolicyProperties());
        return new ProcessService(new SessionSupport(store, cipher, fp),
                new DetectionPipeline(engine, new GreedySpanResolver(), new ComboEvaluator(), policies), metrics, new ru.alfagen.pdsecurity.observability.TokenCounter());
    }

    private String mask(String text) {
        service = newService();
        return service.process(text, "m-" + System.nanoTime()).result();
    }

    @Test
    void passportFullyMasked() {
        String out = mask("паспорт 4509 123456");
        assertFalse(out.contains("123456"), "passport number leaked: " + out);
        assertFalse(out.contains("4509"), "passport series leaked: " + out);
    }

    @Test
    void cardFullyMasked() {
        String out = mask("карта 4276380123456789");
        assertFalse(out.contains("4276380123456789"), "card leaked: " + out);
    }

    @Test
    void innFullyMasked() {
        String out = mask("ИНН 7707083893");
        assertFalse(out.contains("7707083893"), "INN leaked: " + out);
    }

    @Test
    void driverLicenseFullyMasked() {
        String out = mask("ВУ 7712345678");
        assertFalse(out.contains("7712345678"), "license leaked: " + out);
    }

    @Test
    void lengthPreserved() {
        String input = "паспорт 4509 123456, карта 4276380123456789, ИНН 7707083893";
        String out = mask(input);
        assertEquals(input.length(), out.length(), "length mismatch: " + out);
    }

    @Test
    void noOriginalDigitsRemain() {
        String input = "паспорт 4509 123456, карта 4276380123456789, ИНН 7707083893, ВУ 7712345678";
        String out = mask(input);
        for (char c : input.toCharArray()) {
            if (Character.isDigit(c)) {
                assertFalse(out.contains(String.valueOf(c)), "digit " + c + " leaked in: " + out);
            }
        }
    }

    @Test
    void addressDoesNotCrossSentenceBoundary() {
        String out = mask("Адрес: г. Москва, ул. Тверская, д. 7, кв. 15. Позвоните завтра.");
        assertTrue(out.contains("Позвоните завтра"), "trailing clause masked: " + out);
        assertFalse(out.contains("Тверская"), "street leaked: " + out);
    }

    @Test
    void addressDoesNotCapturePhoneClause() {
        String out = mask("Клиент проживает по адресу 125009 Москва Тверская 7, телефон уточняется");
        assertTrue(out.contains("телефон уточняется"), "phone clause masked: " + out);
    }

    @Test
    void cityMentionNotMasked() {
        String out = mask("В городе Москва открылся новый филиал");
        assertEquals("В городе Москва открылся новый филиал", out, "city mention masked: " + out);
    }

    @Test
    void emailHiddenEntirely() {
        String out = mask("email ivan.petrov@mail.ru");
        assertFalse(out.contains("ivan.petrov@mail.ru"), "email leaked: " + out);
        assertFalse(out.contains("@"), "email @ leaked: " + out);
        assertFalse(out.contains("petrov"), "email local part leaked: " + out);
    }

    @Test
    void standaloneStreetDetected() {
        String out = mask("ул. Тверская");
        assertFalse(out.contains("Тверская"), "street leaked: " + out);
    }

    @Test
    void standaloneHouseDetected() {
        String out = mask("дом 28");
        assertFalse(out.contains("28"), "house number leaked: " + out);
    }

    @Test
    void standaloneApartmentDetected() {
        String out = mask("кв. 15");
        assertFalse(out.contains("15"), "apartment leaked: " + out);
    }

    @Test
    void standaloneIndexDetected() {
        String out = mask("индекс 125009");
        assertFalse(out.contains("125009"), "index leaked: " + out);
    }

    @Test
    void standaloneCityDetected() {
        String out = mask("город Москва");
        assertFalse(out.contains("Москва"), "city leaked: " + out);
    }

    @Test
    void fullAddressComponentsDetected() {
        String out = mask("г. Москва, ул. Тверская, д. 7");
        assertFalse(out.contains("Москва"), "city leaked: " + out);
        assertFalse(out.contains("Тверская"), "street leaked: " + out);
        assertFalse(out.contains("7"), "house leaked: " + out);
    }

    @Test
    void labelWordNotMasked() {
        String out = mask("проживает по адресу: Москва, Тверская 7");
        assertTrue(out.contains("адресу"), "label word masked: " + out);
        assertFalse(out.contains("Москва"), "city leaked: " + out);
        assertFalse(out.contains("Тверская"), "street leaked: " + out);
    }

    @Test
    void hyphenatedToponymMasked() {
        String out = mask("адрес регистрации: 344002, Ростов-на-Дону, Большая Садовая 47");
        assertFalse(out.contains("Ростов-на-Дону"), "toponym leaked: " + out);
        assertFalse(out.contains("344002"), "index leaked: " + out);
        assertFalse(out.contains("Большая Садовая"), "street leaked: " + out);
    }

    @Test
    void longDashSeparatorHandled() {
        String out = mask("Мой домашний адрес — Москва, Ленинский проспект 32, кв 118");
        assertFalse(out.contains("Москва"), "city leaked: " + out);
        assertFalse(out.contains("Ленинский проспект"), "street leaked: " + out);
    }
}