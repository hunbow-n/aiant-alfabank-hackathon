package ru.alfagen.pdsecurity.detect;

import java.util.List;

/**
 * The 17 personal-data entity types recognised by the service, plus a marker
 * for "all types" used in policy configuration.
 */
public enum EntityType {
    PERSON,
    BIRTH_DATE,
    BIRTH_PLACE,
    PASSPORT,
    CITIZENSHIP,
    PASSPORT_ISSUER,
    DEPARTMENT_CODE,
    PASSPORT_ISSUE_DATE,
    DRIVER_LICENSE,
    ADDRESS,
    EMAIL,
    PHONE,
    INN,
    CARD,
    CVV,
    PIN,
    CARDHOLDER;

    private static final List<EntityType> ALL_TYPES = List.of(values());

    public static List<EntityType> all() {
        return ALL_TYPES;
    }
}