package ru.alfagen.pdsecurity.detect.rules;

import java.util.Map;

/**
 * Parses Russian number words (cardinal and ordinal) into integers. Supports
 * the forms needed for dates in words: days up to 31 and years up to 2100.
 */
public final class NumberWords {

    private static final Map<String, Integer> UNITS = Map.ofEntries(
            Map.entry("один", 1), Map.entry("одна", 1), Map.entry("первого", 1),
            Map.entry("два", 2), Map.entry("две", 2), Map.entry("второго", 2),
            Map.entry("три", 3), Map.entry("третьего", 3),
            Map.entry("четыре", 4), Map.entry("четвертого", 4), Map.entry("четвёртого", 4),
            Map.entry("пять", 5), Map.entry("пятого", 5),
            Map.entry("шесть", 6), Map.entry("шестого", 6),
            Map.entry("семь", 7), Map.entry("седьмого", 7),
            Map.entry("восемь", 8), Map.entry("восьмого", 8),
            Map.entry("девять", 9), Map.entry("девятого", 9),
            Map.entry("десять", 10), Map.entry("десятого", 10),
            Map.entry("одиннадцать", 11), Map.entry("одиннадцатого", 11),
            Map.entry("двенадцать", 12), Map.entry("двенадцатого", 12),
            Map.entry("тринадцать", 13), Map.entry("тринадцатого", 13),
            Map.entry("четырнадцать", 14), Map.entry("четырнадцатого", 14),
            Map.entry("пятнадцать", 15), Map.entry("пятнадцатого", 15),
            Map.entry("шестнадцать", 16), Map.entry("шестнадцатого", 16),
            Map.entry("семнадцать", 17), Map.entry("семнадцатого", 17),
            Map.entry("восемнадцать", 18), Map.entry("восемнадцатого", 18),
            Map.entry("девятнадцать", 19), Map.entry("девятнадцатого", 19),
            Map.entry("двадцать", 20), Map.entry("двадцатого", 20),
            Map.entry("тридцать", 30), Map.entry("тридцатого", 30),
            Map.entry("сорок", 40), Map.entry("сорокового", 40),
            Map.entry("пятьдесят", 50), Map.entry("пятидесятого", 50),
            Map.entry("шестьдесят", 60), Map.entry("шестидесятого", 60),
            Map.entry("семьдесят", 70), Map.entry("семидесятого", 70),
            Map.entry("восемьдесят", 80), Map.entry("восьмидесятого", 80),
            Map.entry("девяносто", 90), Map.entry("девяностого", 90),
            Map.entry("сто", 100), Map.entry("сотого", 100),
            Map.entry("двести", 200), Map.entry("двухсотого", 200),
            Map.entry("триста", 300), Map.entry("трехсотого", 300), Map.entry("трёхсотого", 300),
            Map.entry("четыреста", 400), Map.entry("четырехсотого", 400), Map.entry("четырёхсотого", 400),
            Map.entry("пятьсот", 500), Map.entry("пятисотого", 500),
            Map.entry("шестьсот", 600), Map.entry("шестисотого", 600),
            Map.entry("семьсот", 700), Map.entry("семисотого", 700),
            Map.entry("восемьсот", 800), Map.entry("восьмисотого", 800),
            Map.entry("девятьсот", 900), Map.entry("девятисотого", 900),
            Map.entry("тысяча", 1000), Map.entry("тысячи", 1000));

    private static final Map<String, Integer> TENS = Map.of(
            "двадцать", 20, "тридцать", 30, "сорок", 40, "пятьдесят", 50,
            "шестьдесят", 60, "семьдесят", 70, "восемьдесят", 80, "девяносто", 90);

    private static final Map<String, Integer> HUNDREDS = Map.of(
            "сто", 100, "двести", 200, "триста", 300, "четыреста", 400, "пятьсот", 500,
            "шестьсот", 600, "семьсот", 700, "восемьсот", 800, "девятьсот", 900);

    private NumberWords() {
    }

    /**
     * Parse a cardinal number phrase like "тысяча девятьсот девяносто".
     */
    public static Integer parseCardinal(String phrase) {
        String[] words = phrase.trim().toLowerCase().split("\\s+");
        int total = 0;
        int current = 0;
        for (String w : words) {
            Integer unit = UNITS.get(w);
            if (unit == null) {
                return null;
            }
            if (unit == 1000) {
                total += (current == 0 ? 1 : current) * 1000;
                current = 0;
            } else if (unit >= 100) {
                current += unit;
            } else if (unit >= 10) {
                current += unit;
            } else {
                current += unit;
            }
        }
        return total + current;
    }

    /**
     * Parse an ordinal day phrase like "двенадцатого".
     */
    public static Integer parseOrdinal(String phrase) {
        String[] words = phrase.trim().toLowerCase().split("\\s+");
        if (words.length == 1) {
            return UNITS.get(words[0]);
        }
        // "двадцать первого" -> 21
        if (words.length == 2) {
            Integer tens = TENS.get(words[0]);
            Integer unit = UNITS.get(words[1]);
            if (tens != null && unit != null && unit <= 9) {
                return tens + unit;
            }
        }
        return null;
    }
}