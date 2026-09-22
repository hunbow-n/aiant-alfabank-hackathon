package ru.alfagen.pdsecurity;

import org.junit.jupiter.api.Test;
import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.DetectionContext;
import ru.alfagen.pdsecurity.detect.Detector;
import ru.alfagen.pdsecurity.detect.EntityType;
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
import ru.alfagen.pdsecurity.resolve.GreedySpanResolver;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.EnumSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Positive and negative fixtures for each of the 17 detectors.
 */
class DetectorFixturesTest {

    private static final DetectionContext CTX = new DetectionContext("balanced", EnumSet.allOf(EntityType.class));

    private List<Candidate> detect(Detector d, String text) {
        return d.detect(new SourceText(text), CTX);
    }

    @Test
    void emailPositive() {
        assertEquals(1, detect(new EmailDetector(), "свяжитесь: ivan.petrov@example.com пожалуйста").size());
    }

    @Test
    void emailNegativeTrailingDot() {
        assertTrue(detect(new EmailDetector(), "пишите на a@b.com.").isEmpty());
    }

    @Test
    void phonePositive() {
        assertEquals(1, detect(new PhoneDetector(), "тел +7 912 345-67-89").size());
    }

    @Test
    void phoneNegativeDate() {
        assertTrue(detect(new PhoneDetector(), "дата 12.03.1990").isEmpty());
    }

    @Test
    void innPositive() {
        assertEquals(1, detect(new InnDetector(), "ИНН 7707083893").size());
    }

    @Test
    void cardPositive() {
        assertEquals(1, detect(new CardDetector(), "карта 4111 1111 1111 1111").size());
    }

    @Test
    void cvvPositive() {
        assertEquals(1, detect(new CvvDetector(), "CVV 123").size());
    }

    @Test
    void cvvNegativeBareDigits() {
        assertTrue(detect(new CvvDetector(), "число 123").isEmpty());
    }

    @Test
    void pinPositive() {
        assertEquals(1, detect(new PinDetector(), "ПИН-код 1234").size());
    }

    @Test
    void pinNegativeYear() {
        assertTrue(detect(new PinDetector(), "год 2024").isEmpty());
    }

    @Test
    void passportPositive() {
        assertEquals(1, detect(new PassportDetector(), "паспорт 45 09 123456").size());
    }

    @Test
    void departmentCodePositive() {
        assertEquals(1, detect(new DepartmentCodeDetector(), "код подразделения 770-001").size());
    }

    @Test
    void driverLicensePositive() {
        assertEquals(1, detect(new DriverLicenseDetector(), "ВУ 7712345678").size());
    }

    @Test
    void birthDatePositive() {
        assertEquals(1, detect(new BirthDateDetector(), "дата рождения 12.03.1990").size());
    }

    @Test
    void birthDateNegativeMeeting() {
        assertTrue(detect(new BirthDateDetector(), "встреча 12.03.1990").isEmpty());
    }

    @Test
    void birthDateInWords() {
        assertEquals(1, detect(new DateWordsDetector(),
                "Родился двенадцатого марта тысяча девятьсот девяностого года").size());
    }

    @Test
    void birthPlacePositive() {
        assertEquals(1, detect(new BirthPlaceDetector(), "место рождения: Москва").size());
    }

    @Test
    void citizenshipPositive() {
        assertEquals(1, detect(new CitizenshipDetector(), "гражданство: Россия").size());
    }

    @Test
    void passportIssuerPositive() {
        assertEquals(1, detect(new PassportIssuerDetector(), "кем выдан: ОВД района Москвы").size());
    }

    @Test
    void passportIssueDatePositive() {
        assertEquals(1, detect(new PassportIssueDateDetector(), "дата выдачи 15.05.2015").size());
    }

    @Test
    void addressPositive() {
        List<Candidate> found = detect(new AddressDetector(), "адрес: г. Москва, ул. Ленина, д. 5");
        List<Candidate> resolved = new GreedySpanResolver().resolve("адрес: г. Москва, ул. Ленина, д. 5", found);
        assertEquals(1, resolved.size());
        assertEquals(EntityType.ADDRESS, resolved.get(0).type());
    }

    @Test
    void addressBankBranchNotMasked() {
        assertTrue(detect(new AddressDetector(), "Адрес отделения банка: г. Москва, ул. Каланчевская, д. 27").isEmpty());
    }

    @Test
    void snilsPositive() {
        assertEquals(1, detect(new SnilsDetector(), "СНИЛС 112-233-445 95").size());
    }

    @Test
    void cardholderPositive() {
        assertEquals(1, detect(new CardholderDetector(), "имя держателя: IVANOV IVAN").size());
    }

    @Test
    void personPositive() {
        assertEquals(1, detect(new PersonDetector(), "клиент Иванов Иван Иванович").size());
    }

    @Test
    void personSurnameFirst() {
        assertEquals(1, detect(new PersonDetector(), "Иванов Иван Иванович").size());
    }

    @Test
    void personSurnameFirstTwo() {
        assertEquals(1, detect(new PersonDetector(), "Петров Иван").size());
    }

    @Test
    void personDeclined() {
        assertEquals(1, detect(new PersonDetector(), "Петрову Сергею Алексеевичу").size());
    }

    @Test
    void personFieldLabels() {
        assertTrue(detect(new PersonDetector(), "Фамилия: Сидоров, Имя: Дмитрий, Отчество: Олегович").size() >= 1);
    }

    @Test
    void personPatronymicSuffixIch() {
        assertEquals(1, detect(new PersonDetector(), "Иван Иванович").size());
    }

    @Test
    void personNegativePublicRole() {
        assertTrue(detect(new PersonDetector(), "поэт Александр Пушкин").isEmpty());
    }
}