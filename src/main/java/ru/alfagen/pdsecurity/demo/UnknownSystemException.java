package ru.alfagen.pdsecurity.demo;

/**
 * Thrown when the demo page asks for a consumer system that is absent from the
 * configuration or disabled in it.
 */
public class UnknownSystemException extends RuntimeException {

    public UnknownSystemException(String system) {
        super("unknown or disabled system: " + system);
    }
}
