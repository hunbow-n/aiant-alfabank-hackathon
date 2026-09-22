package ru.alfagen.pdsecurity.demo;

/**
 * Mock LLM that echoes the prompt back with a small transformation, used to
 * demonstrate token restoration without a real model.
 */
public final class MockLlmClient implements LlmClient {

    @Override
    public String complete(String prompt) {
        return "Ответ модели: " + prompt;
    }
}