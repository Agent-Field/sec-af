package recontext

import "strings"

// This file ports two Python modules verbatim:
//
//	src/sec_af/agents/hunt/_language_hints.py   (LANGUAGE_PATTERNS, get_language_hints)
//	src/sec_af/agents/hunt/_framework_hints.py  (FRAMEWORK_PATTERNS, _FRAMEWORK_ALIASES,
//	                                             _normalize_framework, get_framework_hints)
//
// WHY THEY LIVE HERE AND NOT IN internal/agents/hunt
// -------------------------------------------------
// In Python the dependency runs hunt -> context: `sec_af/context.py` imports
// `get_framework_hints`/`get_language_hints` out of the `sec_af.agents.hunt`
// package, and each hunter module imports `language_hints_for_context` back out
// of `sec_af.context`. Python tolerates that because `agents/hunt/__init__.py`
// is not executed by importing the two leaf hint modules.
//
// Go has no such escape hatch: `internal/agents/hunt` will import
// `internal/recontext` (every hunter needs recon_context_for_*), so if the hint
// tables lived in the hunt package the two packages would import each other and
// the build would fail with an import cycle. The tables are therefore hosted
// here — the package that both sides already depend on — and exported as
// GetLanguageHints / GetFrameworkHints so `internal/agents/hunt` can call them
// directly wherever Python calls them directly.
//
// The table CONTENT is byte-exact with the Python source; every string below is
// a transcription, and the golden tests in hints_test.go compare the rendered
// output against the Python functions run over the same inputs.

// LanguagePattern is one entry of Python's LANGUAGE_PATTERNS.
//
// Python types it `dict[str, list[str] | str]` and reads it with `.get(key)`,
// so a missing key and an empty list behave identically (both falsy, both skip
// the line). A Go struct with zero values reproduces that exactly.
type LanguagePattern struct {
	InjectionSinks     []string
	SafePatterns       []string
	DoNotFlag          []string
	FrameworkSpecifics string
}

// LanguagePatterns ports _language_hints.py LANGUAGE_PATTERNS.
//
// Keyed by the LOWERCASE language name, because get_language_hints lowercases
// every detected language before the lookup.
var LanguagePatterns = map[string]LanguagePattern{
	"python": {
		InjectionSinks: []string{"cursor.execute", "os.system", "subprocess.run", "eval", "exec", "pickle.loads"},
		SafePatterns: []string{
			"parameterized queries with %s placeholders",
			"subprocess.run with list args (no shell=True)",
		},
		DoNotFlag: []string{
			"Django ORM queries (uses parameterized queries internally)",
			"SQLAlchemy text() with bound params",
		},
		FrameworkSpecifics: "Check for Django/Flask/FastAPI-specific patterns. Django auto-escapes templates. Flask Jinja2 auto-escapes.",
	},
	"javascript": {
		InjectionSinks:     []string{"eval", "Function()", "innerHTML", "document.write", "child_process.exec", "new Function"},
		SafePatterns:       []string{"DOMPurify.sanitize()", "textContent assignment", "parameterized pg queries"},
		DoNotFlag:          []string{"React JSX expressions (auto-escaped)", "Angular template bindings (sanitized by default)"},
		FrameworkSpecifics: "Check for React/Vue/Angular-specific XSS patterns. React auto-escapes JSX. Vue v-html is dangerous.",
	},
	"typescript": {
		InjectionSinks:     []string{"eval", "Function()", "innerHTML", "document.write", "child_process.exec"},
		SafePatterns:       []string{"DOMPurify.sanitize()", "textContent assignment", "Prisma parameterized queries"},
		DoNotFlag:          []string{"React JSX expressions", "Angular template bindings", "Prisma ORM queries"},
		FrameworkSpecifics: "TypeScript adds type safety but doesn't prevent injection. Check for any type assertions near user input.",
	},
	"go": {
		InjectionSinks: []string{"fmt.Sprintf into SQL", "exec.Command with user input", "template.HTML()", "os.Exec"},
		SafePatterns: []string{
			"database/sql with ? placeholders",
			"html/template (auto-escapes)",
			"exec.Command with separate args",
		},
		DoNotFlag: []string{
			"GORM parameterized queries",
			"html/template default escaping",
			"database/sql prepared statements",
		},
		FrameworkSpecifics: "Go's html/template auto-escapes. text/template does NOT. Check for text/template serving HTML.",
	},
	"java": {
		InjectionSinks: []string{
			"Statement.execute",
			"Runtime.exec",
			"ProcessBuilder with concatenated strings",
			"ScriptEngine.eval",
		},
		SafePatterns:       []string{"PreparedStatement with ?", "JNDI lookup with allowlist", "OWASP ESAPI encoding"},
		DoNotFlag:          []string{"JPA/Hibernate named parameters", "Spring Security CSRF protection", "PreparedStatement usage"},
		FrameworkSpecifics: "Check Spring Boot auto-config. Thymeleaf auto-escapes. JSP needs explicit escaping.",
	},
	"ruby": {
		InjectionSinks: []string{"eval", "system", "exec", "send", "public_send", "ERB.new with user input"},
		SafePatterns:   []string{"ActiveRecord parameterized queries", "Rack::Utils.escape_html", "sanitize helper in Rails"},
		DoNotFlag: []string{
			"ActiveRecord where with hash conditions",
			"Rails CSRF protection",
			"Rails html_safe on constants",
		},
		FrameworkSpecifics: "Rails auto-escapes ERB templates. raw/html_safe bypasses escaping. Check for mass assignment.",
	},
	"csharp": {
		InjectionSinks:     []string{"SqlCommand with concatenation", "Process.Start with user input", "Razor @Html.Raw()"},
		SafePatterns:       []string{"SqlParameter", "Entity Framework LINQ", "Razor auto-encoding"},
		DoNotFlag:          []string{"Entity Framework LINQ queries", "ASP.NET anti-forgery tokens", "Razor default encoding"},
		FrameworkSpecifics: "ASP.NET Core Razor auto-encodes. @Html.Raw() is dangerous. Check for [ValidateAntiForgeryToken].",
	},
}

// GetLanguageHints ports _language_hints.py get_language_hints:
//
//	detected = [lang.lower() for lang in languages]
//	hints = []
//	for lang in detected:
//	    patterns = LANGUAGE_PATTERNS.get(lang)
//	    if patterns is None: continue
//	    section = [f"Language: {lang.upper()}"]
//	    ... four optional lines ...
//	    hints.append("\n".join(section))
//	if not hints: return "No language-specific hints available for detected languages."
//	return "LANGUAGE-SPECIFIC GUIDANCE:\n" + "\n\n".join(hints)
//
// Python parity notes:
//
//   - There is NO deduplication, unlike get_framework_hints. `["Python",
//     "python"]` emits the PYTHON section twice, and this reproduces that.
//   - The heading uses `lang.upper()` on the ALREADY-LOWERCASED name, so the
//     spelling always comes from the table key, never from the caller's casing.
//   - Go's strings.ToLower/ToUpper are Unicode-aware like Python's
//     str.lower()/str.upper(), with the usual rare divergences on characters
//     whose case mapping changes length (Python maps U+0130 to two code points,
//     Go to one). No language name in the table is affected.
func GetLanguageHints(languages []string) string {
	hints := make([]string, 0, len(languages))
	for _, raw := range languages {
		lang := strings.ToLower(raw)
		patterns, ok := LanguagePatterns[lang]
		if !ok {
			continue
		}
		section := []string{"Language: " + strings.ToUpper(lang)}
		if len(patterns.InjectionSinks) > 0 {
			section = append(section, "  Key sinks: "+strings.Join(patterns.InjectionSinks, ", "))
		}
		if len(patterns.SafePatterns) > 0 {
			section = append(section, "  Safe patterns (skip these): "+strings.Join(patterns.SafePatterns, ", "))
		}
		if len(patterns.DoNotFlag) > 0 {
			section = append(section, "  DO NOT FLAG: "+strings.Join(patterns.DoNotFlag, ", "))
		}
		if patterns.FrameworkSpecifics != "" {
			section = append(section, "  Framework notes: "+patterns.FrameworkSpecifics)
		}
		hints = append(hints, strings.Join(section, "\n"))
	}
	if len(hints) == 0 {
		return "No language-specific hints available for detected languages."
	}
	return "LANGUAGE-SPECIFIC GUIDANCE:\n" + strings.Join(hints, "\n\n")
}

// FrameworkPattern is one entry of Python's FRAMEWORK_PATTERNS
// (`dict[str, dict[str, list[str]]]` — every entry has all four keys, and
// get_framework_hints indexes them directly rather than using .get()).
type FrameworkPattern struct {
	SecurityFeatures []string
	DoNotFlag        []string
	WatchFor         []string
	CommonVulns      []string
}

// FrameworkPatterns ports _framework_hints.py FRAMEWORK_PATTERNS, keyed by the
// NORMALIZED framework name (see normalizeFramework).
var FrameworkPatterns = map[string]FrameworkPattern{
	"django": {
		SecurityFeatures: []string{
			"ORM queries are parameterized by default",
			"Templates auto-escape variables by default",
			"CsrfViewMiddleware enforces CSRF tokens for unsafe methods",
		},
		DoNotFlag: []string{
			"Django ORM filter/exclude (parameterized)",
			"CSRF with CsrfViewMiddleware active",
			"XSS in Django templates (auto-escaped)",
		},
		WatchFor: []string{"raw() queries", "mark_safe()", "|safe filter", "CSRF_COOKIE_SECURE=False"},
		CommonVulns: []string{
			"SQL injection via raw SQL and string formatting",
			"XSS via unsafe template escape bypasses",
			"CSRF weakening via middleware/settings overrides",
		},
	},
	"flask": {
		SecurityFeatures: []string{
			"Jinja2 auto-escapes in HTML templates",
			"Werkzeug handles request parsing safely by default",
			"Blueprint/middleware patterns can centralize auth checks",
		},
		DoNotFlag: []string{
			"Jinja2 auto-escaped template variables",
			"Parameterized SQLAlchemy query usage",
			"Server-side session signing with strong SECRET_KEY",
		},
		WatchFor: []string{
			"render_template_string() with user input",
			"debug=True in production paths",
			"string-concatenated SQL in execute()",
			"hardcoded SECRET_KEY",
		},
		CommonVulns: []string{
			"SSTI through dynamic template rendering",
			"XSS when auto-escaping is bypassed",
			"session tampering risk with weak secret/config",
		},
	},
	"fastapi": {
		SecurityFeatures: []string{
			"Pydantic request validation reduces malformed input",
			"Dependency injection supports reusable auth guards",
			"OpenAPI schema generation improves contract visibility",
		},
		DoNotFlag: []string{
			"Pydantic model validation errors",
			"Dependency-based auth checks clearly enforced",
			"Parameterized SQLAlchemy/async driver usage",
		},
		WatchFor: []string{
			"Depends() omitted on privileged routes",
			"raw SQL in text()/execute() with interpolation",
			"CORS allow_origins=['*'] with credentials",
			"unsafe deserialization in background tasks",
		},
		CommonVulns: []string{
			"Auth bypass on unprotected routes",
			"SQL injection in manually assembled queries",
			"CORS misconfiguration exposing credentialed APIs",
		},
	},
	"express": {
		SecurityFeatures: []string{
			"Router middleware can enforce auth and rate limits",
			"helmet can apply secure HTTP headers",
			"Validated schema middleware can constrain input",
		},
		DoNotFlag: []string{
			"Parameterized ORM/database queries",
			"helmet defaults correctly applied",
			"router-level auth middleware consistently enforced",
		},
		WatchFor: []string{
			"res.send()/res.json() leaking sensitive internals",
			"string-built SQL in query()",
			"trust proxy misconfiguration",
			"open CORS with credentials",
		},
		CommonVulns: []string{
			"Authz gaps from missing middleware on routes",
			"NoSQL/SQL injection from unsanitized request bodies",
			"Open redirect and SSRF through unvalidated URLs",
		},
	},
	"nextjs": {
		SecurityFeatures: []string{
			"React JSX auto-escapes output by default",
			"API routes can share centralized auth middleware",
			"Server/client boundaries reduce accidental secret exposure",
		},
		DoNotFlag: []string{
			"React JSX escaped rendering",
			"getServerSideProps/getServerSession with proper auth checks",
			"Typed route handlers with validated schema guards",
		},
		WatchFor: []string{
			"dangerouslySetInnerHTML",
			"unprotected API routes under /api",
			"secret leakage to client bundles",
			"rewrites/redirects from untrusted user input",
		},
		CommonVulns: []string{
			"XSS through dangerous HTML rendering",
			"IDOR/auth bypass in API handlers",
			"Sensitive env/config exposure in client-side code",
		},
	},
	"spring": {
		SecurityFeatures: []string{
			"Spring Security provides auth, CSRF, and filter chain defaults",
			"JPA/Hibernate prepared parameter binding by default",
			"Bean validation can enforce request constraints",
		},
		DoNotFlag: []string{
			"PreparedStatement/JPA named parameter usage",
			"Spring Security CSRF/auth filters clearly active",
			"Thymeleaf auto-escaped output",
		},
		WatchFor: []string{
			"@PreAuthorize missing on sensitive methods",
			"JdbcTemplate/raw Statement with concatenation",
			"csrf().disable() on browser session flows",
			"Actuator endpoints exposed without auth",
		},
		CommonVulns: []string{
			"Authz bypass from weak method-level security",
			"SQL injection in raw JDBC queries",
			"Sensitive management endpoint exposure",
		},
	},
	"rails": {
		SecurityFeatures: []string{
			"ActiveRecord parameterization for hash/array queries",
			"ERB templates auto-escape by default",
			"Built-in CSRF protection for non-GET requests",
		},
		DoNotFlag: []string{
			"ActiveRecord where with hash conditions",
			"Rails protect_from_forgery active",
			"ERB escaped output without raw/html_safe",
		},
		WatchFor: []string{
			"where/order/find_by_sql with string interpolation",
			"raw()/html_safe on untrusted content",
			"skip_before_action on auth filters",
			"mass assignment via permit!",
		},
		CommonVulns: []string{
			"SQL injection in manual query fragments",
			"XSS via unsafe output helpers",
			"Authz bypass from skipped controller guards",
		},
	},
	"aspnet": {
		SecurityFeatures: []string{
			"Razor encodes output by default",
			"Model binding and data annotations aid validation",
			"Anti-forgery tokens support CSRF defense",
		},
		DoNotFlag: []string{
			"Entity Framework LINQ parameterized queries",
			"Razor default HTML encoding",
			"ValidateAntiForgeryToken in state-changing MVC actions",
		},
		WatchFor: []string{
			"Html.Raw() on untrusted input",
			"FromBody models without validation",
			"Authorize missing on privileged endpoints",
			"custom SQL built via string interpolation",
		},
		CommonVulns: []string{
			"XSS through Html.Raw and unencoded output",
			"Auth/authz bypass on unsecured controllers",
			"SQL injection in handcrafted query strings",
		},
	},
	"react": {
		SecurityFeatures: []string{
			"JSX escapes strings before DOM rendering",
			"Component model encourages explicit data flow",
			"Framework discourages direct DOM mutation",
		},
		DoNotFlag: []string{
			"Standard JSX expression rendering",
			"textContent assignment for untrusted text",
			"sanitized HTML via trusted DOMPurify policy",
		},
		WatchFor: []string{
			"dangerouslySetInnerHTML",
			"untrusted URL assignment to href/src",
			"eval/new Function in client code",
			"token/secret exposure in bundles",
		},
		CommonVulns: []string{
			"DOM XSS through unsafe HTML injection",
			"Open redirect via unvalidated navigation targets",
			"Sensitive data exposure in frontend artifacts",
		},
	},
	"vue": {
		SecurityFeatures: []string{
			"Mustache template interpolation escapes HTML",
			"Component props/events provide explicit boundaries",
			"Router guards can enforce auth flows",
		},
		DoNotFlag: []string{
			"escaped template interpolation {{ value }}",
			"validated route guards protecting private routes",
			"sanitized content rendered through safe components",
		},
		WatchFor: []string{
			"v-html with untrusted data",
			"dynamic component/template compilation",
			"unsafe URL bindings in href/src",
			"client-side auth checks without server enforcement",
		},
		CommonVulns: []string{
			"XSS through v-html and unsafe render paths",
			"Auth bypass from client-only route protection",
			"Open redirect patterns in router navigation",
		},
	},
	"angular": {
		SecurityFeatures: []string{
			"Template binding sanitization for HTML/URL contexts",
			"HttpClient and interceptor patterns support central controls",
			"AOT compilation limits runtime template injection vectors",
		},
		DoNotFlag: []string{
			"default Angular template binding sanitization",
			"HttpClient usage with validated request schemas",
			"route guards consistently applied",
		},
		WatchFor: []string{
			"bypassSecurityTrustHtml/Url/Script",
			"[innerHTML] with unsanitized input",
			"direct DOM APIs via ElementRef/nativeElement",
			"auth only in client guard without server checks",
		},
		CommonVulns: []string{
			"XSS when sanitizer is explicitly bypassed",
			"Token leakage in local storage/logging",
			"Authorization gaps due to client-only enforcement",
		},
	},
}

// frameworkAliases ports _framework_hints.py _FRAMEWORK_ALIASES.
var frameworkAliases = map[string]string{
	"next":          "nextjs",
	"next.js":       "nextjs",
	"springboot":    "spring",
	"spring-boot":   "spring",
	"spring boot":   "spring",
	"asp.net":       "aspnet",
	"asp.net core":  "aspnet",
	"aspnetcore":    "aspnet",
	"asp net":       "aspnet",
	"ruby on rails": "rails",
}

// normalizeFramework ports _normalize_framework:
//
//	lowered = value.strip().lower()
//	return _FRAMEWORK_ALIASES.get(lowered, lowered)
//
// Python parity: `str.strip()` with no argument strips Unicode whitespace;
// strings.TrimSpace strips the same class (unicode.IsSpace). The two differ
// only on a handful of exotic code points that no framework name contains.
func normalizeFramework(value string) string {
	lowered := strings.ToLower(strings.TrimSpace(value))
	if alias, ok := frameworkAliases[lowered]; ok {
		return alias
	}
	return lowered
}

// GetFrameworkHints ports _framework_hints.py get_framework_hints.
//
// Python parity: the normalized names are deduplicated while PRESERVING FIRST
// APPEARANCE ORDER (Python builds `ordered_unique` with a linear `in` check on
// a list, not a set), so `["Next", "next.js"]` yields one NEXTJS section, and
// unknown frameworks silently drop out of the output but still consume their
// slot in the dedup list.
func GetFrameworkHints(frameworks []string) string {
	orderedUnique := make([]string, 0, len(frameworks))
	for _, framework := range frameworks {
		normalized := normalizeFramework(framework)
		seen := false
		for _, existing := range orderedUnique {
			if existing == normalized {
				seen = true
				break
			}
		}
		if seen {
			continue
		}
		orderedUnique = append(orderedUnique, normalized)
	}

	sections := make([]string, 0, len(orderedUnique))
	for _, framework := range orderedUnique {
		patterns, ok := FrameworkPatterns[framework]
		if !ok {
			continue
		}
		section := []string{"Framework: " + strings.ToUpper(framework)}
		if len(patterns.SecurityFeatures) > 0 {
			section = append(section, "  Security features: "+strings.Join(patterns.SecurityFeatures, ", "))
		}
		if len(patterns.DoNotFlag) > 0 {
			section = append(section, "  DO NOT FLAG: "+strings.Join(patterns.DoNotFlag, ", "))
		}
		if len(patterns.WatchFor) > 0 {
			section = append(section, "  Watch for: "+strings.Join(patterns.WatchFor, ", "))
		}
		if len(patterns.CommonVulns) > 0 {
			section = append(section, "  Common vulns: "+strings.Join(patterns.CommonVulns, ", "))
		}
		sections = append(sections, strings.Join(section, "\n"))
	}

	if len(sections) == 0 {
		return "No framework-specific hints available for detected frameworks."
	}
	return "FRAMEWORK-SPECIFIC GUIDANCE:\n" + strings.Join(sections, "\n\n")
}
