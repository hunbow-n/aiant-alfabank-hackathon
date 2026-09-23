package ru.alfagen.pdsecurity.demo;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.DetectionContext;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.mask.MaskStrategy;
import ru.alfagen.pdsecurity.mask.Masker;
import ru.alfagen.pdsecurity.mask.StarMask;
import ru.alfagen.pdsecurity.mask.SyntheticMask;
import ru.alfagen.pdsecurity.mask.TokenMask;
import ru.alfagen.pdsecurity.policy.PolicySnapshot;
import ru.alfagen.pdsecurity.service.DetectionPipeline;
import ru.alfagen.pdsecurity.text.SourceRange;
import ru.alfagen.pdsecurity.text.SourceText;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Runs the full demo round trip: detect, mask, ask a model, restore. State is
 * kept inside a single call, so this path never touches the correlation store
 * used by the evaluated {@code /process} endpoint.
 */
public final class DemoService {

    private static final String DEFAULT_SYSTEM = "chat-assistant";

    private final DetectionPipeline pipeline;
    private final LlmClient mock;
    private final LlmClient alfaGen;

    public DemoService(DetectionPipeline pipeline, LlmClient mock, LlmClient alfaGen) {
        this.pipeline = pipeline;
        this.mock = mock;
        this.alfaGen = alfaGen;
    }

    public DemoRunResponse run(DemoRunRequest request) {
        String system = request.system() == null || request.system().isBlank()
                ? DEFAULT_SYSTEM : request.system();
        PolicySnapshot policy = pipeline.policies().get(system);
        if (policy == null || !policy.enabled()) {
            throw new UnknownSystemException(system);
        }
        String strategyName = request.strategy() == null || request.strategy().isBlank()
                ? policy.strategy() : request.strategy();

        long t0 = System.nanoTime();
        List<Candidate> candidates = pipeline.engine().detect(new SourceText(request.text()),
                new DetectionContext(policy.ambiguityMode(), policy.detectTypes()));
        candidates = pipeline.comboEvaluator().apply(candidates, policy);
        List<Candidate> resolved = pipeline.resolver().resolve(request.text(), candidates);
        long detectNanos = System.nanoTime() - t0;

        long t1 = System.nanoTime();
        MaskStrategy strategy = strategyFor(strategyName);
        String masked = new Masker(strategy).render(request.text(), resolved);
        long maskNanos = System.nanoTime() - t1;

        long t2 = System.nanoTime();
        String note = null;
        String llmMode = "alfagen".equals(request.llmMode()) ? "alfagen" : "mock";
        String answer;
        try {
            answer = ("alfagen".equals(llmMode) ? alfaGen : mock).complete(masked);
        } catch (RuntimeException e) {
            answer = mock.complete(masked);
            llmMode = "mock";
            note = "Модель недоступна, ответ получен от встроенного мока.";
        }
        long llmNanos = System.nanoTime() - t2;

        long t3 = System.nanoTime();
        Map<String, String> reverse = reverseTable(strategy);
        String restored = restore(answer, reverse);
        long restoreNanos = System.nanoTime() - t3;

        // Микросекунды: модуль укладывается в доли миллисекунды, целые мс показывали бы ноль.
        Map<String, Long> timings = new LinkedHashMap<>();
        timings.put("detect", micros(detectNanos));
        timings.put("mask", micros(maskNanos));
        timings.put("llm", micros(llmNanos));
        timings.put("restore", micros(restoreNanos));
        timings.put("moduleTotal", micros(detectNanos + maskNanos + restoreNanos));

        return new DemoRunResponse(request.text(), masked, answer, restored,
                typeCounts(resolved), fragments(request.text(), resolved), timings,
                llmMode, strategyName, system, policy.maskTypes().size(),
                notCovered(request.text(), policy), note);
    }

    /**
     * Типы, которые есть в тексте, но не входят в перечень этой системы. Нужны
     * демо-странице, чтобы отличить настройку политики от пропуска детектора.
     */
    private List<String> notCovered(String text, PolicySnapshot policy) {
        if (policy.maskTypes().size() >= EntityType.all().size()) {
            return List.of();
        }
        List<Candidate> all = pipeline.engine().detect(new SourceText(text),
                new DetectionContext(policy.ambiguityMode(), Set.copyOf(EntityType.all())));
        return all.stream()
                .map(c -> c.type())
                .filter(type -> !policy.maskTypes().contains(type))
                .map(EntityType::name)
                .distinct()
                .toList();
    }

    /**
     * Replaces every known placeholder inside the model answer. Longest values
     * first, so one replacement never eats a prefix of another.
     */
    private String restore(String text, Map<String, String> reverse) {
        if (reverse.isEmpty()) {
            return text;
        }
        List<String> keys = new ArrayList<>(reverse.keySet());
        keys.sort(Comparator.comparingInt(String::length).reversed());
        String result = text;
        for (String key : keys) {
            result = result.replace(key, reverse.get(key));
        }
        return result;
    }

    private Map<String, String> reverseTable(MaskStrategy strategy) {
        if (strategy instanceof TokenMask token) {
            Map<String, String> reverse = new LinkedHashMap<>();
            // Ключ таблицы — "ТИП\u0000значение"; для восстановления нужна только часть после разделителя.
            token.tokenTable().forEach((key, placeholder) -> {
                int sep = key.indexOf('\u0000');
                reverse.put(placeholder, sep < 0 ? key : key.substring(sep + 1));
            });
            return reverse;
        }
        if (strategy instanceof SyntheticMask synthetic) {
            return synthetic.reverseTable();
        }
        return Map.of();
    }

    private Map<String, Integer> typeCounts(List<Candidate> candidates) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (Candidate c : candidates) {
            counts.merge(c.type().name(), 1, Integer::sum);
        }
        return counts;
    }

    private List<String> fragments(String source, List<Candidate> candidates) {
        List<String> out = new ArrayList<>();
        for (Candidate c : candidates) {
            StringBuilder value = new StringBuilder();
            for (SourceRange r : c.ranges()) {
                value.append(source, r.startInclusive(), r.endExclusive()).append(' ');
            }
            out.add(c.type().name() + ": " + value.toString().trim());
        }
        return out;
    }

    private MaskStrategy strategyFor(String name) {
        return switch (name) {
            case "token" -> new TokenMask();
            case "synthetic" -> new SyntheticMask();
            default -> new StarMask();
        };
    }

    private long micros(long nanos) {
        return nanos / 1_000;
    }
}
