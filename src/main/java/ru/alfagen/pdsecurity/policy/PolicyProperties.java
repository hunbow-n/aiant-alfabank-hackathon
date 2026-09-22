package ru.alfagen.pdsecurity.policy;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Binds the {@code pd.policy} YAML configuration. The benchmark namespace is
 * always present and reserved; consumer systems are configured under
 * {@code systems}.
 */
@ConfigurationProperties(prefix = "pd.policy")
public class PolicyProperties {

    private long version = 1;
    private Benchmark benchmark = new Benchmark();
    private Map<String, SystemConfig> systems = new LinkedHashMap<>();

    public long getVersion() {
        return version;
    }

    public void setVersion(long version) {
        this.version = version;
    }

    public Benchmark getBenchmark() {
        return benchmark;
    }

    public void setBenchmark(Benchmark benchmark) {
        this.benchmark = benchmark;
    }

    public Map<String, SystemConfig> getSystems() {
        return systems;
    }

    public void setSystems(Map<String, SystemConfig> systems) {
        this.systems = systems;
    }

    public static class Benchmark {
        private boolean enabled = true;
        private String namespace = "benchmark";
        private List<String> detectTypes = List.of("ALL");
        private List<String> maskTypes = List.of("ALL");
        private boolean demask = true;
        private String ambiguityMode = "balanced";
        private String strategy = "star";
        private String activeTtl = "15m";
        private String tombstoneTtl = "5m";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getNamespace() {
            return namespace;
        }

        public void setNamespace(String namespace) {
            this.namespace = namespace;
        }

        public List<String> getDetectTypes() {
            return detectTypes;
        }

        public void setDetectTypes(List<String> detectTypes) {
            this.detectTypes = detectTypes;
        }

        public List<String> getMaskTypes() {
            return maskTypes;
        }

        public void setMaskTypes(List<String> maskTypes) {
            this.maskTypes = maskTypes;
        }

        public boolean isDemask() {
            return demask;
        }

        public void setDemask(boolean demask) {
            this.demask = demask;
        }

        public String getAmbiguityMode() {
            return ambiguityMode;
        }

        public void setAmbiguityMode(String ambiguityMode) {
            this.ambiguityMode = ambiguityMode;
        }

        public String getStrategy() {
            return strategy;
        }

        public void setStrategy(String strategy) {
            this.strategy = strategy;
        }

        public String getActiveTtl() {
            return activeTtl;
        }

        public void setActiveTtl(String activeTtl) {
            this.activeTtl = activeTtl;
        }

        public String getTombstoneTtl() {
            return tombstoneTtl;
        }

        public void setTombstoneTtl(String tombstoneTtl) {
            this.tombstoneTtl = tombstoneTtl;
        }
    }

    public static class SystemConfig {
        private boolean enabled = true;
        private String apiKeyHashRef;
        private List<String> detectTypes;
        private List<String> maskTypes;
        private boolean demask = true;
        private String ambiguityMode = "contextual";
        private String strategy = "token";
        private List<ComboRuleConfig> comboRules = List.of();

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getApiKeyHashRef() {
            return apiKeyHashRef;
        }

        public void setApiKeyHashRef(String apiKeyHashRef) {
            this.apiKeyHashRef = apiKeyHashRef;
        }

        public List<String> getDetectTypes() {
            return detectTypes;
        }

        public void setDetectTypes(List<String> detectTypes) {
            this.detectTypes = detectTypes;
        }

        public List<String> getMaskTypes() {
            return maskTypes;
        }

        public void setMaskTypes(List<String> maskTypes) {
            this.maskTypes = maskTypes;
        }

        public boolean isDemask() {
            return demask;
        }

        public void setDemask(boolean demask) {
            this.demask = demask;
        }

        public String getAmbiguityMode() {
            return ambiguityMode;
        }

        public void setAmbiguityMode(String ambiguityMode) {
            this.ambiguityMode = ambiguityMode;
        }

        public String getStrategy() {
            return strategy;
        }

        public void setStrategy(String strategy) {
            this.strategy = strategy;
        }

        public List<ComboRuleConfig> getComboRules() {
            return comboRules;
        }

        public void setComboRules(List<ComboRuleConfig> comboRules) {
            this.comboRules = comboRules;
        }
    }

    public static class ComboRuleConfig {
        private List<String> targetTypes;
        private List<String> requireTypes;
        private String scope = "field_group";

        public List<String> getTargetTypes() {
            return targetTypes;
        }

        public void setTargetTypes(List<String> targetTypes) {
            this.targetTypes = targetTypes;
        }

        public List<String> getRequireTypes() {
            return requireTypes;
        }

        public void setRequireTypes(List<String> requireTypes) {
            this.requireTypes = requireTypes;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }
    }
}