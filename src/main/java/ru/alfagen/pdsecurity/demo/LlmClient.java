package ru.alfagen.pdsecurity.demo;

/**
 * Abstraction over an LLM client used only by the demo endpoint. Never called
 * from /process.
 */
public interface LlmClient {

    String complete(String prompt);
}