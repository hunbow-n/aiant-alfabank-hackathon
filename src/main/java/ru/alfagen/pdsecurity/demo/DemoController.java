package ru.alfagen.pdsecurity.demo;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.alfagen.pdsecurity.api.ApiError;
import ru.alfagen.pdsecurity.observability.ProcessingMetrics;
import ru.alfagen.pdsecurity.observability.RecentEvents;
import ru.alfagen.pdsecurity.policy.PolicyRegistry;

import java.util.List;
import java.util.Map;

/**
 * Backs the demo page: one call runs the whole chain and returns every stage
 * so a reviewer can see exactly what left the perimeter. Not part of the
 * evaluated {@code /process} path.
 */
@RestController
@RequestMapping("/demo")
public class DemoController {

    private final DemoService service;
    private final PolicyRegistry policies;
    private final ProcessingMetrics metrics;
    private final RecentEvents recentEvents;
    private final boolean alfaGenConfigured;

    public DemoController(DemoService service, PolicyRegistry policies, ProcessingMetrics metrics,
                          RecentEvents recentEvents, boolean alfaGenConfigured) {
        this.service = service;
        this.policies = policies;
        this.metrics = metrics;
        this.recentEvents = recentEvents;
        this.alfaGenConfigured = alfaGenConfigured;
    }

    /**
     * Агрегаты, которые сервис и так публикует в Prometheus: latency, счётчики
     * запросов и найденных типов. Значений персональных данных здесь нет.
     */
    @GetMapping("/metrics")
    public Map<String, Object> metrics() {
        return metrics.snapshot();
    }

    /**
     * Последние строки журнала обработки — те же, что уходят в лог. Видно типы
     * и количества, но ни одного значения: проверяющий может убедиться сам.
     */
    @GetMapping("/events")
    public List<RecentEvents.Entry> events() {
        return recentEvents.recent();
    }

    @PostMapping("/run")
    public DemoRunResponse run(@Valid @RequestBody DemoRunRequest request) {
        return service.run(request);
    }

    /**
     * Options the page renders: configured consumer systems and whether a real
     * model is available.
     */
    @GetMapping("/options")
    public Map<String, Object> options() {
        List<Map<String, Object>> systems = policies.names().stream()
                .map(name -> {
                    var policy = policies.get(name);
                    return Map.<String, Object>of(
                            "id", name,
                            "enabled", policy.enabled(),
                            "demask", policy.demask(),
                            "strategy", policy.strategy(),
                            "types", policy.maskTypes().size());
                })
                .toList();
        return Map.of("systems", systems, "alfaGen", alfaGenConfigured);
    }

    @ExceptionHandler(UnknownSystemException.class)
    public ResponseEntity<ApiError> handleUnknownSystem(UnknownSystemException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ApiError("unknown_system", "Система не настроена или отключена"));
    }
}
