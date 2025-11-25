use once_cell::sync::Lazy;
use regex::Regex;

/// URL-safe name validation regex
/// Allows: Unicode letters, Unicode numbers, hyphen (-), underscore (_)
/// This includes Korean (한글), Japanese (日本語), Chinese (中文), Arabic (العربية), etc.
static URL_SAFE_NAME_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[\p{L}\p{N}_-]+$").expect("Failed to compile URL safe name regex"));

/// Checks if a name contains only URL-safe characters
/// Supports Unicode characters including Korean (한글), Japanese (日本語), Chinese (中文), etc.
/// Disallows: spaces, special characters like /, ?, &, =, %, etc.
/// Note: Browsers will automatically URL-encode non-ASCII characters (e.g., 한글 → %ED%95%9C%EA%B8%80)
pub fn is_url_safe_name(name: &str) -> bool {
    if name.is_empty() {
        return true; // Empty name is allowed (will be treated as unnamed)
    }
    URL_SAFE_NAME_REGEX.is_match(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_safe_name_valid() {
        assert!(is_url_safe_name(""));
        assert!(is_url_safe_name("test"));
        assert!(is_url_safe_name("test-name"));
        assert!(is_url_safe_name("test_name"));
        assert!(is_url_safe_name("test123"));
        assert!(is_url_safe_name("한글"));
        assert!(is_url_safe_name("日本語"));
        assert!(is_url_safe_name("中文"));
    }

    #[test]
    fn test_url_safe_name_invalid() {
        assert!(!is_url_safe_name("test name")); // space
        assert!(!is_url_safe_name("test/name")); // slash
        assert!(!is_url_safe_name("test?name")); // question mark
        assert!(!is_url_safe_name("test&name")); // ampersand
        assert!(!is_url_safe_name("test=name")); // equals
        assert!(!is_url_safe_name("test%name")); // percent
    }
}
