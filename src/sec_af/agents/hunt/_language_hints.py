"""Language-specific vulnerability patterns and safe idioms for hunt prompts."""

LANGUAGE_PATTERNS: dict[str, dict[str, list[str] | str]] = {
    "python": {
        "injection_sinks": ["cursor.execute", "os.system", "subprocess.run", "eval", "exec", "pickle.loads"],
        "safe_patterns": [
            "parameterized queries with %s placeholders",
            "subprocess.run with list args (no shell=True)",
        ],
        "do_not_flag": [
            "Django ORM queries (uses parameterized queries internally)",
            "SQLAlchemy text() with bound params",
        ],
        "framework_specifics": "Check for Django/Flask/FastAPI-specific patterns. Django auto-escapes templates. Flask Jinja2 auto-escapes.",
    },
    "javascript": {
        "injection_sinks": ["eval", "Function()", "innerHTML", "document.write", "child_process.exec", "new Function"],
        "safe_patterns": ["DOMPurify.sanitize()", "textContent assignment", "parameterized pg queries"],
        "do_not_flag": ["React JSX expressions (auto-escaped)", "Angular template bindings (sanitized by default)"],
        "framework_specifics": "Check for React/Vue/Angular-specific XSS patterns. React auto-escapes JSX. Vue v-html is dangerous.",
    },
    "typescript": {
        "injection_sinks": ["eval", "Function()", "innerHTML", "document.write", "child_process.exec"],
        "safe_patterns": ["DOMPurify.sanitize()", "textContent assignment", "Prisma parameterized queries"],
        "do_not_flag": ["React JSX expressions", "Angular template bindings", "Prisma ORM queries"],
        "framework_specifics": "TypeScript adds type safety but doesn't prevent injection. Check for any type assertions near user input.",
    },
    "go": {
        "injection_sinks": ["fmt.Sprintf into SQL", "exec.Command with user input", "template.HTML()", "os.Exec"],
        "safe_patterns": [
            "database/sql with ? placeholders",
            "html/template (auto-escapes)",
            "exec.Command with separate args",
        ],
        "do_not_flag": [
            "GORM parameterized queries",
            "html/template default escaping",
            "database/sql prepared statements",
        ],
        "framework_specifics": "Go's html/template auto-escapes. text/template does NOT. Check for text/template serving HTML.",
    },
    "java": {
        "injection_sinks": [
            "Statement.execute",
            "Runtime.exec",
            "ProcessBuilder with concatenated strings",
            "ScriptEngine.eval",
        ],
        "safe_patterns": ["PreparedStatement with ?", "JNDI lookup with allowlist", "OWASP ESAPI encoding"],
        "do_not_flag": ["JPA/Hibernate named parameters", "Spring Security CSRF protection", "PreparedStatement usage"],
        "framework_specifics": "Check Spring Boot auto-config. Thymeleaf auto-escapes. JSP needs explicit escaping.",
    },
    "ruby": {
        "injection_sinks": ["eval", "system", "exec", "send", "public_send", "ERB.new with user input"],
        "safe_patterns": ["ActiveRecord parameterized queries", "Rack::Utils.escape_html", "sanitize helper in Rails"],
        "do_not_flag": [
            "ActiveRecord where with hash conditions",
            "Rails CSRF protection",
            "Rails html_safe on constants",
        ],
        "framework_specifics": "Rails auto-escapes ERB templates. raw/html_safe bypasses escaping. Check for mass assignment.",
    },
    "csharp": {
        "injection_sinks": ["SqlCommand with concatenation", "Process.Start with user input", "Razor @Html.Raw()"],
        "safe_patterns": ["SqlParameter", "Entity Framework LINQ", "Razor auto-encoding"],
        "do_not_flag": ["Entity Framework LINQ queries", "ASP.NET anti-forgery tokens", "Razor default encoding"],
        "framework_specifics": "ASP.NET Core Razor auto-encodes. @Html.Raw() is dangerous. Check for [ValidateAntiForgeryToken].",
    },
}


def get_language_hints(languages: list[str]) -> str:
    """Build language-specific hints string from detected languages."""
    detected = [lang.lower() for lang in languages]
    hints: list[str] = []
    for lang in detected:
        patterns = LANGUAGE_PATTERNS.get(lang)
        if patterns is None:
            continue
        section = [f"Language: {lang.upper()}"]
        if patterns.get("injection_sinks"):
            section.append(f"  Key sinks: {', '.join(patterns['injection_sinks'])}")
        if patterns.get("safe_patterns"):
            section.append(f"  Safe patterns (skip these): {', '.join(patterns['safe_patterns'])}")
        if patterns.get("do_not_flag"):
            section.append(f"  DO NOT FLAG: {', '.join(patterns['do_not_flag'])}")
        if patterns.get("framework_specifics"):
            section.append(f"  Framework notes: {patterns['framework_specifics']}")
        hints.append("\n".join(section))
    if not hints:
        return "No language-specific hints available for detected languages."
    return "LANGUAGE-SPECIFIC GUIDANCE:\n" + "\n\n".join(hints)
