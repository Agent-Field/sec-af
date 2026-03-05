FRAMEWORK_PATTERNS: dict[str, dict[str, list[str]]] = {
    "django": {
        "security_features": [
            "ORM queries are parameterized by default",
            "Templates auto-escape variables by default",
            "CsrfViewMiddleware enforces CSRF tokens for unsafe methods",
        ],
        "do_not_flag": [
            "Django ORM filter/exclude (parameterized)",
            "CSRF with CsrfViewMiddleware active",
            "XSS in Django templates (auto-escaped)",
        ],
        "watch_for": ["raw() queries", "mark_safe()", "|safe filter", "CSRF_COOKIE_SECURE=False"],
        "common_vulns": [
            "SQL injection via raw SQL and string formatting",
            "XSS via unsafe template escape bypasses",
            "CSRF weakening via middleware/settings overrides",
        ],
    },
    "flask": {
        "security_features": [
            "Jinja2 auto-escapes in HTML templates",
            "Werkzeug handles request parsing safely by default",
            "Blueprint/middleware patterns can centralize auth checks",
        ],
        "do_not_flag": [
            "Jinja2 auto-escaped template variables",
            "Parameterized SQLAlchemy query usage",
            "Server-side session signing with strong SECRET_KEY",
        ],
        "watch_for": [
            "render_template_string() with user input",
            "debug=True in production paths",
            "string-concatenated SQL in execute()",
            "hardcoded SECRET_KEY",
        ],
        "common_vulns": [
            "SSTI through dynamic template rendering",
            "XSS when auto-escaping is bypassed",
            "session tampering risk with weak secret/config",
        ],
    },
    "fastapi": {
        "security_features": [
            "Pydantic request validation reduces malformed input",
            "Dependency injection supports reusable auth guards",
            "OpenAPI schema generation improves contract visibility",
        ],
        "do_not_flag": [
            "Pydantic model validation errors",
            "Dependency-based auth checks clearly enforced",
            "Parameterized SQLAlchemy/async driver usage",
        ],
        "watch_for": [
            "Depends() omitted on privileged routes",
            "raw SQL in text()/execute() with interpolation",
            "CORS allow_origins=['*'] with credentials",
            "unsafe deserialization in background tasks",
        ],
        "common_vulns": [
            "Auth bypass on unprotected routes",
            "SQL injection in manually assembled queries",
            "CORS misconfiguration exposing credentialed APIs",
        ],
    },
    "express": {
        "security_features": [
            "Router middleware can enforce auth and rate limits",
            "helmet can apply secure HTTP headers",
            "Validated schema middleware can constrain input",
        ],
        "do_not_flag": [
            "Parameterized ORM/database queries",
            "helmet defaults correctly applied",
            "router-level auth middleware consistently enforced",
        ],
        "watch_for": [
            "res.send()/res.json() leaking sensitive internals",
            "string-built SQL in query()",
            "trust proxy misconfiguration",
            "open CORS with credentials",
        ],
        "common_vulns": [
            "Authz gaps from missing middleware on routes",
            "NoSQL/SQL injection from unsanitized request bodies",
            "Open redirect and SSRF through unvalidated URLs",
        ],
    },
    "nextjs": {
        "security_features": [
            "React JSX auto-escapes output by default",
            "API routes can share centralized auth middleware",
            "Server/client boundaries reduce accidental secret exposure",
        ],
        "do_not_flag": [
            "React JSX escaped rendering",
            "getServerSideProps/getServerSession with proper auth checks",
            "Typed route handlers with validated schema guards",
        ],
        "watch_for": [
            "dangerouslySetInnerHTML",
            "unprotected API routes under /api",
            "secret leakage to client bundles",
            "rewrites/redirects from untrusted user input",
        ],
        "common_vulns": [
            "XSS through dangerous HTML rendering",
            "IDOR/auth bypass in API handlers",
            "Sensitive env/config exposure in client-side code",
        ],
    },
    "spring": {
        "security_features": [
            "Spring Security provides auth, CSRF, and filter chain defaults",
            "JPA/Hibernate prepared parameter binding by default",
            "Bean validation can enforce request constraints",
        ],
        "do_not_flag": [
            "PreparedStatement/JPA named parameter usage",
            "Spring Security CSRF/auth filters clearly active",
            "Thymeleaf auto-escaped output",
        ],
        "watch_for": [
            "@PreAuthorize missing on sensitive methods",
            "JdbcTemplate/raw Statement with concatenation",
            "csrf().disable() on browser session flows",
            "Actuator endpoints exposed without auth",
        ],
        "common_vulns": [
            "Authz bypass from weak method-level security",
            "SQL injection in raw JDBC queries",
            "Sensitive management endpoint exposure",
        ],
    },
    "rails": {
        "security_features": [
            "ActiveRecord parameterization for hash/array queries",
            "ERB templates auto-escape by default",
            "Built-in CSRF protection for non-GET requests",
        ],
        "do_not_flag": [
            "ActiveRecord where with hash conditions",
            "Rails protect_from_forgery active",
            "ERB escaped output without raw/html_safe",
        ],
        "watch_for": [
            "where/order/find_by_sql with string interpolation",
            "raw()/html_safe on untrusted content",
            "skip_before_action on auth filters",
            "mass assignment via permit!",
        ],
        "common_vulns": [
            "SQL injection in manual query fragments",
            "XSS via unsafe output helpers",
            "Authz bypass from skipped controller guards",
        ],
    },
    "aspnet": {
        "security_features": [
            "Razor encodes output by default",
            "Model binding and data annotations aid validation",
            "Anti-forgery tokens support CSRF defense",
        ],
        "do_not_flag": [
            "Entity Framework LINQ parameterized queries",
            "Razor default HTML encoding",
            "ValidateAntiForgeryToken in state-changing MVC actions",
        ],
        "watch_for": [
            "Html.Raw() on untrusted input",
            "FromBody models without validation",
            "Authorize missing on privileged endpoints",
            "custom SQL built via string interpolation",
        ],
        "common_vulns": [
            "XSS through Html.Raw and unencoded output",
            "Auth/authz bypass on unsecured controllers",
            "SQL injection in handcrafted query strings",
        ],
    },
    "react": {
        "security_features": [
            "JSX escapes strings before DOM rendering",
            "Component model encourages explicit data flow",
            "Framework discourages direct DOM mutation",
        ],
        "do_not_flag": [
            "Standard JSX expression rendering",
            "textContent assignment for untrusted text",
            "sanitized HTML via trusted DOMPurify policy",
        ],
        "watch_for": [
            "dangerouslySetInnerHTML",
            "untrusted URL assignment to href/src",
            "eval/new Function in client code",
            "token/secret exposure in bundles",
        ],
        "common_vulns": [
            "DOM XSS through unsafe HTML injection",
            "Open redirect via unvalidated navigation targets",
            "Sensitive data exposure in frontend artifacts",
        ],
    },
    "vue": {
        "security_features": [
            "Mustache template interpolation escapes HTML",
            "Component props/events provide explicit boundaries",
            "Router guards can enforce auth flows",
        ],
        "do_not_flag": [
            "escaped template interpolation {{ value }}",
            "validated route guards protecting private routes",
            "sanitized content rendered through safe components",
        ],
        "watch_for": [
            "v-html with untrusted data",
            "dynamic component/template compilation",
            "unsafe URL bindings in href/src",
            "client-side auth checks without server enforcement",
        ],
        "common_vulns": [
            "XSS through v-html and unsafe render paths",
            "Auth bypass from client-only route protection",
            "Open redirect patterns in router navigation",
        ],
    },
    "angular": {
        "security_features": [
            "Template binding sanitization for HTML/URL contexts",
            "HttpClient and interceptor patterns support central controls",
            "AOT compilation limits runtime template injection vectors",
        ],
        "do_not_flag": [
            "default Angular template binding sanitization",
            "HttpClient usage with validated request schemas",
            "route guards consistently applied",
        ],
        "watch_for": [
            "bypassSecurityTrustHtml/Url/Script",
            "[innerHTML] with unsanitized input",
            "direct DOM APIs via ElementRef/nativeElement",
            "auth only in client guard without server checks",
        ],
        "common_vulns": [
            "XSS when sanitizer is explicitly bypassed",
            "Token leakage in local storage/logging",
            "Authorization gaps due to client-only enforcement",
        ],
    },
}

_FRAMEWORK_ALIASES: dict[str, str] = {
    "next": "nextjs",
    "next.js": "nextjs",
    "springboot": "spring",
    "spring-boot": "spring",
    "spring boot": "spring",
    "asp.net": "aspnet",
    "asp.net core": "aspnet",
    "aspnetcore": "aspnet",
    "asp net": "aspnet",
    "ruby on rails": "rails",
}


def _normalize_framework(value: str) -> str:
    lowered = value.strip().lower()
    return _FRAMEWORK_ALIASES.get(lowered, lowered)


def get_framework_hints(frameworks: list[str]) -> str:
    ordered_unique: list[str] = []
    for framework in frameworks:
        normalized = _normalize_framework(framework)
        if normalized in ordered_unique:
            continue
        ordered_unique.append(normalized)

    sections: list[str] = []
    for framework in ordered_unique:
        patterns = FRAMEWORK_PATTERNS.get(framework)
        if patterns is None:
            continue
        section = [f"Framework: {framework.upper()}"]
        if patterns["security_features"]:
            section.append(f"  Security features: {', '.join(patterns['security_features'])}")
        if patterns["do_not_flag"]:
            section.append(f"  DO NOT FLAG: {', '.join(patterns['do_not_flag'])}")
        if patterns["watch_for"]:
            section.append(f"  Watch for: {', '.join(patterns['watch_for'])}")
        if patterns["common_vulns"]:
            section.append(f"  Common vulns: {', '.join(patterns['common_vulns'])}")
        sections.append("\n".join(section))

    if not sections:
        return "No framework-specific hints available for detected frameworks."
    return "FRAMEWORK-SPECIFIC GUIDANCE:\n" + "\n\n".join(sections)
