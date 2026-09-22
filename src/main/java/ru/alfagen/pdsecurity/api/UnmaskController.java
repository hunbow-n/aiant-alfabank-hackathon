package ru.alfagen.pdsecurity.api;

import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.alfagen.pdsecurity.security.SystemAuthentication;
import ru.alfagen.pdsecurity.service.ConsumerService;

/**
 * Consumer unmasking endpoint. Requires X-System-Id and X-Api-Key headers.
 */
@RestController
@RequestMapping("/api/v1")
public class UnmaskController {

    private final ConsumerService service;
    private final SystemAuthentication auth;

    public UnmaskController(ConsumerService service, SystemAuthentication auth) {
        this.service = service;
        this.auth = auth;
    }

    @PostMapping("/unmask")
    public ResponseEntity<ProcessResponse> unmask(
            @RequestHeader(value = "X-System-Id", required = false) String systemId,
            @RequestHeader(value = "X-Api-Key", required = false) String apiKey,
            @Valid @RequestBody ProcessRequest request) {
        String authenticated = auth.authenticate(systemId, apiKey);
        if (authenticated == null) {
            return ResponseEntity.status(401).body(new ProcessResponse(""));
        }
        String result = service.unmask(authenticated, request.payload(), request.payloadId());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(new ProcessResponse(result));
    }
}