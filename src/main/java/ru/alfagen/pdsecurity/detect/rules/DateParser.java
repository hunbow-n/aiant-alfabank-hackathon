package ru.alfagen.pdsecurity.detect.rules;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses dates in DMY, MDY, YMD, YDM forms with separators '.', '/', '-', space,
 * 4-digit or 2-digit years, and Russian month names. Returns the matched range
 * and a flag for whether the day/month are plausible.
 */
public final class DateParser {

    private static final Pattern NUMERIC = Pattern.compile(
            "(\\d{1,2})[./\\-\\s](\\d{1,2})[./\\-\\s](\\d{2,4})");

    private static final Pattern VERBAL = Pattern.compile(
            "(?iu)(\\d{1,2})\\s+(января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)"
                    + "\\s+(\\d{4})");

    private static final String[] MONTHS = {
            "января", "февраля", "марта", "апреля", "мая", "июня",
            "июля", "августа", "сентября", "октября", "ноября", "декабря"};

    public record ParsedDate(int start, int end, boolean plausible) {
    }

    public ParsedDate find(String text, int from) {
        Matcher nm = NUMERIC.matcher(text);
        if (nm.find(from)) {
            int d = Integer.parseInt(nm.group(1));
            int mo = Integer.parseInt(nm.group(2));
            int y = Integer.parseInt(nm.group(3));
            boolean plausible = d >= 1 && d <= 31 && mo >= 1 && mo <= 12 && y >= 1900 && y <= 2100;
            return new ParsedDate(nm.start(), nm.end(), plausible);
        }
        Matcher vm = VERBAL.matcher(text);
        if (vm.find(from)) {
            int d = Integer.parseInt(vm.group(1));
            int mo = indexOfMonth(vm.group(2));
            int y = Integer.parseInt(vm.group(3));
            boolean plausible = d >= 1 && d <= 31 && mo >= 0 && y >= 1900 && y <= 2100;
            return new ParsedDate(vm.start(), vm.end(), plausible);
        }
        return null;
    }

    private int indexOfMonth(String name) {
        for (int i = 0; i < MONTHS.length; i++) {
            if (MONTHS[i].equalsIgnoreCase(name)) {
                return i + 1;
            }
        }
        return -1;
    }
}