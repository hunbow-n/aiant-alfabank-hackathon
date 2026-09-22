package ru.alfagen.pdsecurity.demo;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.alfagen.pdsecurity.api.ProcessRequest;
import ru.alfagen.pdsecurity.api.ProcessResponse;
import ru.alfagen.pdsecurity.service.ConsumerService;

/**
 * Demo endpoint: masks a payload, sends it to a mock LLM, and returns the
 * model response. Requires X-System-Id and X-Api-Key headers. Not part of the
 * evaluated /process path.
 */
@RestController
@RequestMapping("/demo")
public class DemoController {

    private final ConsumerService service;
    private final LlmClient llm;

    public DemoController(ConsumerService service, LlmClient llm) {
        this.service = service;
        this.llm = llm;
    }

    @PostMapping("/mask")
    public ProcessResponse mask(@RequestBody ProcessRequest request) {
        String masked = service.mask("crm-bot", request.payload(), request.payloadId());
        return new ProcessResponse(masked);
    }

    @PostMapping("/llm")
    public ProcessResponse llm(@RequestBody ProcessRequest request) {
        String masked = service.mask("crm-bot", request.payload(), request.payloadId());
        String response = llm.complete(masked);
        return new ProcessResponse(response);
    }
}