package ru.alfagen.pdsecurity.api;

import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import ru.alfagen.pdsecurity.service.ProcessService;

/**
 * The evaluated endpoint. Handles both masking and demasking based on the
 * session state for the given payload_id. No authentication is required.
 */
@RestController
public class ProcessController {

    private final ProcessService service;

    public ProcessController(ProcessService service) {
        this.service = service;
    }

    @PostMapping("/process")
    public ResponseEntity<ProcessResponse> process(@Valid @RequestBody ProcessRequest request) {
        ProcessService.ProcessResult result = service.process(request.payload(), request.payloadId());
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(new ProcessResponse(result.result()));
    }
}