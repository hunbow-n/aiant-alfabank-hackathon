package ru.alfagen.pdsecurity.detect.rules;

import ru.alfagen.pdsecurity.detect.Candidate;
import ru.alfagen.pdsecurity.detect.DetectionContext;
import ru.alfagen.pdsecurity.detect.Detector;
import ru.alfagen.pdsecurity.detect.EntityType;
import ru.alfagen.pdsecurity.text.SearchToken;
import ru.alfagen.pdsecurity.text.SourceRange;
import ru.alfagen.pdsecurity.text.SourceText;
import ru.alfagen.pdsecurity.text.TextTokenizer;

import java.util.ArrayList;
import java.util.List;

/**
 * Detects person names in the common document forms: "Фамилия Имя Отчество",
 * "Имя Отчество", "Имя Фамилия", and field-labelled "Фамилия:/Имя:/Отчество:".
 * A name is a run of 2-3 consecutive capitalized tokens where at least one is a
 * known first name or patronymic, or the run matches surname+name+patronymic.
 * Public roles ("поэт Александр Пушкин") are not masked in balanced mode.
 */
public final class PersonDetector implements Detector {

    private static final TextTokenizer TOKENIZER = new TextTokenizer();

    private static final List<String> PERSONAL_LABELS = List.of(
            "клиент", "гражданин", "гражданка", "заявитель", "заявительница",
            "пациент", "пациентка", "сотрудник", "сотрудница", "пользователь",
            "держатель", "владелец", "абонент", "страхователь");

    private static final List<String> PUBLIC_LABELS = List.of(
            "поэт", "писатель", "художник", "композитор", "ученый", "учёный",
            "президент", "министр", "актер", "актёр", "певец", "певица");

    private static final List<String> FIELD_LABELS = List.of(
            "фамилия", "имя", "отчество");

    @Override
    public EntityType type() {
        return EntityType.PERSON;
    }

    @Override
    public List<Candidate> detect(SourceText source, DetectionContext context) {
        List<Candidate> out = new ArrayList<>();
        List<SearchToken> tokens = TOKENIZER.tokenize(source.value());

        for (int i = 0; i < tokens.size(); i++) {
            SearchToken t = tokens.get(i);
            String norm = t.normalizedValue();

            // Field-labelled name: "Фамилия: Сидоров, Имя: Дмитрий, Отчество: Олегович"
            if (FIELD_LABELS.contains(norm) && isFieldLabel(source, t)) {
                Candidate c = tryFieldName(source, tokens, i);
                if (c != null) {
                    out.add(c);
                    i = advancePast(tokens, c);
                    continue;
                }
            }

            // Full name starting from a first name: "Иван Иванович Иванов", "Иван Петров"
            if (NameDictionary.isFirstName(norm)) {
                Candidate c = tryFromFirstName(source, tokens, i, context);
                if (c != null) {
                    out.add(c);
                    i = advancePast(tokens, c);
                    continue;
                }
            }

            // Full name starting from a surname: "Иванов Иван Иванович", "Петров Иван"
            if (NameDictionary.looksLikeSurname(norm)) {
                Candidate c = tryFromSurname(source, tokens, i, context);
                if (c != null) {
                    out.add(c);
                    i = advancePast(tokens, c);
                    continue;
                }
            }

            // Single name with personal label.
            if (NameDictionary.isFirstName(norm) && hasPersonalLabelBefore(tokens, i)) {
                out.add(new Candidate("p-" + t.originalRange().startInclusive(), EntityType.PERSON,
                        List.of(t.originalRange()), 0.8, 90, "person-label", null));
            }
        }
        return out;
    }

    private Candidate tryFromFirstName(SourceText source, List<SearchToken> tokens, int i, DetectionContext context) {
        int n = tokens.size();
        // first + patronymic + surname
        if (i + 2 < n && NameDictionary.looksLikePatronymic(tokens.get(i + 1).normalizedValue())
                && NameDictionary.looksLikeSurname(tokens.get(i + 2).normalizedValue())) {
            return build(source, tokens, i, i + 3, context);
        }
        // first + surname
        if (i + 1 < n && NameDictionary.looksLikeSurname(tokens.get(i + 1).normalizedValue())) {
            return build(source, tokens, i, i + 2, context);
        }
        // first + patronymic (no surname)
        if (i + 1 < n && NameDictionary.looksLikePatronymic(tokens.get(i + 1).normalizedValue())) {
            return build(source, tokens, i, i + 2, context);
        }
        return null;
    }

    private Candidate tryFromSurname(SourceText source, List<SearchToken> tokens, int i, DetectionContext context) {
        int n = tokens.size();
        // surname + first + patronymic
        if (i + 2 < n && NameDictionary.isFirstName(tokens.get(i + 1).normalizedValue())
                && NameDictionary.looksLikePatronymic(tokens.get(i + 2).normalizedValue())) {
            return build(source, tokens, i, i + 3, context);
        }
        // surname + first
        if (i + 1 < n && NameDictionary.isFirstName(tokens.get(i + 1).normalizedValue())) {
            return build(source, tokens, i, i + 2, context);
        }
        return null;
    }

    private Candidate tryFieldName(SourceText source, List<SearchToken> tokens, int i) {
        int n = tokens.size();
        // "Фамилия: Сидоров" -> value is the next token
        if (i + 1 < n) {
            String value = tokens.get(i + 1).normalizedValue();
            if (NameDictionary.looksLikeSurname(value) || NameDictionary.isFirstName(value)
                    || NameDictionary.looksLikePatronymic(value)) {
                return build(source, tokens, i + 1, i + 2, null);
            }
        }
        return null;
    }

    private Candidate build(SourceText source, List<SearchToken> tokens, int start, int end, DetectionContext context) {
        if (context != null && hasPublicLabelBefore(tokens, start) && "balanced".equals(context.ambiguityMode())) {
            return null;
        }
        SourceRange range = new SourceRange(
                tokens.get(start).originalRange().startInclusive(),
                tokens.get(end - 1).originalRange().endExclusive());
        return new Candidate("p-" + range.startInclusive(), EntityType.PERSON,
                List.of(range), 0.85, 90, "person-name", null);
    }

    private boolean isFieldLabel(SourceText source, SearchToken t) {
        // A field label is followed by ':' or ',' within a few chars.
        int idx = t.originalRange().endExclusive();
        int limit = Math.min(source.length(), idx + 3);
        for (int j = idx; j < limit; j++) {
            char c = source.charAt(j);
            if (c == ':') {
                return true;
            }
            if (c == ',' || c == '\n') {
                return false;
            }
        }
        return false;
    }

    private boolean hasPersonalLabelBefore(List<SearchToken> tokens, int i) {
        for (int j = Math.max(0, i - 3); j < i; j++) {
            if (PERSONAL_LABELS.contains(tokens.get(j).normalizedValue())) {
                return true;
            }
        }
        return false;
    }

    private boolean hasPublicLabelBefore(List<SearchToken> tokens, int i) {
        for (int j = Math.max(0, i - 3); j < i; j++) {
            if (PUBLIC_LABELS.contains(tokens.get(j).normalizedValue())) {
                return true;
            }
        }
        return false;
    }

    private int advancePast(List<SearchToken> tokens, Candidate c) {
        int end = c.firstRange().endExclusive();
        for (int i = 0; i < tokens.size(); i++) {
            if (tokens.get(i).originalRange().startInclusive() >= end) {
                return i - 1;
            }
        }
        return tokens.size() - 1;
    }
}