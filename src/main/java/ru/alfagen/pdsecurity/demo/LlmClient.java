package ru.alfagen.pdsecurity.demo;

/**
 * Abstraction over an LLM client used only by the demo endpoint. Never called
 * from /process.
 */
public interface LlmClient {

    /**
     * @param prompt       masked text to send to the model
     * @param instructions system instructions; they differ per mask strategy,
     *                     because a model must copy placeholders verbatim but
     *                     must never invent them for synthetic or star masks
     */
    String complete(String prompt, String instructions);
}
