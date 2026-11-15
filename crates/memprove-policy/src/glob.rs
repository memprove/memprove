//! The patterns of a rule. A command pattern is matched against the words
//! of one simple command joined by single spaces: `*` matches any run of
//! characters, spaces too, and `?` one character; a pattern that ends with
//! ` *` also matches the command without it (`git push *` matches `git
//! push`). A path pattern is matched segment by segment: `*` and `?` stay
//! inside one segment and `**` matches any number of segments.

/// Whether `text` matches `pattern`, `*` matching any run of characters and
/// `?` one character.
#[must_use]
pub fn text_matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    wildcard(&pattern, &text)
}

/// The iterative wildcard match with one backtracking point per `*`.
fn wildcard(pattern: &[char], text: &[char]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((star_p, star_t)) = star {
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, star_t + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|character| *character == '*')
}

/// A command pattern as rules hold it: whitespace runs as one space, and
/// Claude Code's `:*` suffix as ` *`.
#[must_use]
pub fn command_pattern(raw: &str) -> String {
    let joined = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    match joined.strip_suffix(":*") {
        Some(head) => format!("{} *", head.trim_end()),
        None => joined,
    }
}

/// Whether the command `text` (words joined by single spaces) matches the
/// command `pattern` (as [`command_pattern`] gives it).
#[must_use]
pub fn command_matches(pattern: &str, text: &str) -> bool {
    text_matches(pattern, text)
        || pattern
            .strip_suffix(" *")
            .is_some_and(|head| text_matches(head, text))
}

/// Whether the path segment `segment` matches the pattern segment
/// `pattern` (no `/` in either).
#[must_use]
pub fn segment_matches(pattern: &str, segment: &str) -> bool {
    text_matches(pattern, segment)
}

/// Whether the path `path` (its segments) matches `pattern` (its segments,
/// `**` for any number of segments).
#[must_use]
pub fn path_matches(pattern: &[&str], path: &[&str]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        Some((&"**", rest)) => {
            path_matches(rest, path) || (!path.is_empty() && path_matches(pattern, &path[1..]))
        }
        Some((first, rest)) => {
            !path.is_empty() && segment_matches(first, path[0]) && path_matches(rest, &path[1..])
        }
    }
}

/// Whether `pattern` matches `path` or one of its ancestors: a rule on a
/// directory covers what is in it.
#[must_use]
pub fn path_or_ancestor_matches(pattern: &[&str], path: &[&str]) -> bool {
    (1..=path.len()).any(|length| path_matches(pattern, &path[..length])) || pattern.is_empty()
}

/// Whether something at or below `path` could match `pattern`: for a
/// command that changes a whole directory tree (`rm -r`, `git clean`).
#[must_use]
pub fn subtree_may_match(pattern: &[&str], path: &[&str]) -> bool {
    match (pattern.split_first(), path.split_first()) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some((&"**", rest)), Some((_, deeper))) => {
            subtree_may_match(rest, path) || subtree_may_match(pattern, deeper)
        }
        (Some((first, rest)), Some((segment, deeper))) => {
            segment_matches(first, segment) && subtree_may_match(rest, deeper)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stars_match_runs_of_characters_spaces_too() {
        assert!(text_matches(
            "git push *--force*",
            "git push origin main --force"
        ));
        assert!(text_matches(
            "git push *--force*",
            "git push --force-with-lease"
        ));
        assert!(!text_matches("git push *--force*", "git push origin main"));
        assert!(text_matches("rm -?f *", "rm -rf build"));
        assert!(text_matches("*", ""));
        assert!(!text_matches("a", ""));
    }

    #[test]
    fn a_trailing_star_also_matches_nothing() {
        let pattern = command_pattern("git   push:*");
        assert_eq!(pattern, "git push *");
        assert!(command_matches(&pattern, "git push"));
        assert!(command_matches(&pattern, "git push origin x"));
        assert!(!command_matches(&pattern, "git pushx"));
        assert!(!command_matches("git push", "git push origin"));
    }

    #[test]
    fn path_patterns_match_by_segment() {
        let pattern = ["db", "migrations", "**"];
        assert!(path_matches(&pattern, &["db", "migrations", "001.sql"]));
        assert!(path_matches(&pattern, &["db", "migrations", "a", "b.sql"]));
        assert!(path_matches(&pattern, &["db", "migrations"]));
        assert!(!path_matches(&pattern, &["db", "seeds", "x"]));
        assert!(path_matches(&["*.rs"], &["main.rs"]));
        assert!(!path_matches(&["*.rs"], &["src", "main.rs"]));
        assert!(path_matches(&["**", "*.pem"], &["a", "b", "key.pem"]));
    }

    #[test]
    fn a_directory_rule_covers_what_is_in_it() {
        assert!(path_or_ancestor_matches(
            &["secrets"],
            &["secrets", "key.pem"]
        ));
        assert!(!path_or_ancestor_matches(
            &["secrets"],
            &["src", "secrets.rs"]
        ));
    }

    #[test]
    fn a_tree_may_hold_a_match() {
        let pattern = ["db", "migrations", "**"];
        assert!(subtree_may_match(&pattern, &["db"]));
        assert!(subtree_may_match(&pattern, &[]));
        assert!(!subtree_may_match(&pattern, &["src"]));
        assert!(subtree_may_match(&["**", "*.pem"], &["src"]));
    }
}
