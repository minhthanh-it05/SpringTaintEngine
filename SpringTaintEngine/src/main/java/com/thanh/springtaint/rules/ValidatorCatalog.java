package com.thanh.springtaint.rules;

import java.util.List;

/**
 * Registry of validator calls {@code DfgBuilder} recognizes when building the branch-scoped
 * sanitization described on {@link ValidatorRule}.
 *
 * Both rules below used to be listed in {@link SanitizerCatalog}'s javadoc under "Deliberately
 * NOT included": modeling them as ordinary call-based sanitizers there was unsound, because
 * this engine had no way to say "only the branch where the check passed is safe" -- it would
 * have silently cleared taint even on paths where the validating branch was never actually
 * taken. Now that {@code DfgBuilder#processIf} applies validators branch-scoped -- only inside
 * the branch proven to run after the check passed, including the common
 * {@code if (!valid(x)) return;} guard-clause shape -- it's sound to include them here instead.
 */
public class ValidatorCatalog {

    private final List<ValidatorRule> rules;

    public ValidatorCatalog(List<ValidatorRule> rules) {
        this.rules = List.copyOf(rules);
    }

    public static ValidatorCatalog defaults() {
        return new ValidatorCatalog(List.of(
                new ValidatorRule("StringUtils", "isNumeric", 0,
                        "Apache Commons Lang3: true only when every character is a digit, which cannot carry an injection payload"),

                // Pattern.matches(regex, input) -- argument 0 is the regex, argument 1 is the
                // value being tested. We trust the regex is actually restrictive; a
                // deliberately permissive one (e.g. ".*") defeats this the same way it would
                // defeat the real validation -- a known limitation shared with the human
                // reviewer, since this engine doesn't interpret regex semantics.
                new ValidatorRule("Pattern", "matches", 1,
                        "java.util.regex.Pattern: true only when the value fully matches the given pattern")

                // Deliberately NOT included:
                // - Calls reached through an instance receiver built earlier, e.g.
                //   `somePattern.matcher(x).matches()`: recognizing this would require walking a
                //   multi-step call chain back to the Pattern.compile(...) that built the
                //   receiver, which this rule's simple (className, methodName) matching can't
                //   express yet.
                // - Statically-imported calls (bare `isNumeric(x)` with no `StringUtils.`
                //   scope): ValidatorRule matches by simple scope name, same limitation
                //   SinkCatalog/SanitizerCatalog already accept elsewhere in this codebase.
                // - Bean Validation annotations (@Pattern/@NotBlank/@Valid on a @RequestBody
                //   DTO field): a fundamentally different mechanism -- declarative, enforced by
                //   the Spring framework itself before the controller method body ever runs,
                //   not an inline call this engine's intraprocedural DFG walk ever sees. Would
                //   need to resolve the DTO's class, read its field annotations, and recognize
                //   getter calls on it -- a separate feature, not a catalog entry.
        ));
    }

    public List<ValidatorRule> matching(String scopeSimpleName, String methodName) {
        if (scopeSimpleName == null) {
            return List.of();
        }
        return rules.stream().filter(rule -> rule.matches(scopeSimpleName, methodName)).toList();
    }
}
