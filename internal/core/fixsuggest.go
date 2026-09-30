package core

import (
	"fmt"
	"path/filepath"
	"strings"
)

// FixSuggester produces specific, step-by-step remediation guidance for a
// finding, using its category, rule ID and detected language.
type FixSuggester struct{}

// EnrichFixes rewrites generic Fix texts into specific, actionable,
// language-aware remediation steps. Existing detailed fixes are preserved.
func EnrichFixes(findings []Finding) {
	for i := range findings {
		f := &findings[i]
		if isSpecificFix(f.Fix) {
			continue
		}
		if fix := suggest(f); fix != "" {
			f.Fix = fix
		}
	}
}

// isSpecificFix heuristically detects whether a fix text already contains
// actionable detail (command lines, code snippets, numbered steps).
func isSpecificFix(fix string) bool {
	if fix == "" {
		return false
	}
	if strings.Contains(fix, "\n") || strings.Contains(fix, "1.") || strings.Contains(fix, "`") {
		return true
	}
	// Commands like "Run gofmt -w", "Add header X-Frame-Options: DENY"
	return strings.Contains(fix, "Run ") || strings.Contains(fix, ": ") ||
		strings.Contains(fix, "Set ") || strings.Contains(fix, "Replace ")
}

func suggest(f *Finding) string {
	lang := detectLanguage(f.File)
	var b strings.Builder

	switch {
	case f.Category == "formatting" || f.Category == "style":
		formattingFix(&b, f, lang)
	case f.Category == "secrets":
		secretsFix(&b, f)
	case f.Category == "sca":
		scaFix(&b, f)
	case f.Category == "sast" || f.Category == "injection" || f.Category == "xss":
		sastFix(&b, f, lang)
	case f.Category == "iac" || f.Category == "container":
		iacFix(&b, f)
	case f.Category == "security-headers" || f.Category == "transport-security" ||
		f.Category == "cookie-security" || f.Category == "cors" ||
		f.Category == "clickjacking" || f.Category == "information-disclosure":
		headerFix(&b, f)
	case f.Category == "open-redirect":
		redirectFix(&b, f, lang)
	case f.Category == "license":
		licenseFix(&b, f)
	default:
		return ""
	}

	// Trailing context line with exact location for actionable fixes.
	if f.File != "" && f.Line > 0 && b.Len() > 0 {
		fmt.Fprintf(&b, "\nLocation: %s:%d", f.File, f.Line)
	}
	return strings.TrimPrefix(b.String(), "\n")
}

func detectLanguage(file string) string {
	switch strings.ToLower(filepath.Ext(file)) {
	case ".go":
		return "go"
	case ".js", ".mjs", ".cjs", ".jsx":
		return "js"
	case ".ts", ".tsx":
		return "ts"
	case ".py":
		return "python"
	case ".rs":
		return "rust"
	case ".java", ".kt":
		return "jvm"
	case ".rb":
		return "ruby"
	case ".php":
		return "php"
	case ".cs":
		return "csharp"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".tf":
		return "terraform"
	case ".sh", ".bash", ".zsh":
		return "shell"
	case ".html", ".vue", ".svelte":
		return "web"
	default:
		return ""
	}
}

func formattingFix(b *strings.Builder, f *Finding, lang string) {
	switch f.RuleID {
	case "fmt-trailing-whitespace":
		fmt.Fprintf(b, "Remove the trailing spaces at the end of line %d:\n", f.Line)
		fmt.Fprintf(b, "  sed -i '%ds/[ \\t]+$//' %s\n", f.Line, f.File)
		fmt.Fprintf(b, "  or run: iris fmt %s --fix", filepath.Dir(f.File))
	case "fmt-missing-eof-newline":
		fmt.Fprintf(b, "Append the missing final newline:\n")
		fmt.Fprintf(b, "  printf '\\n' >> %s\n", f.File)
		fmt.Fprintf(b, "  or run: iris fmt %s --fix", filepath.Dir(f.File))
	case "fmt-crlf-line-ending":
		fmt.Fprintf(b, "Convert CRLF to LF line endings:\n")
		fmt.Fprintf(b, "  sed -i 's/\\r$//' %s\n", f.File)
		fmt.Fprintf(b, "  Prevent it: add 'end_of_line = lf' to .editorconfig and set core.autocrlf=input in git")
	case "fmt-mixed-indentation":
		switch lang {
		case "go":
			fmt.Fprintf(b, "Go uses tabs for indentation. Re-indent with gofmt:\n  gofmt -w %s", f.File)
		case "python":
			fmt.Fprintf(b, "Python uses 4 spaces. Fix line %d to use spaces only:\n  iris fmt %s --fix", f.Line, f.File)
		default:
			fmt.Fprintf(b, "Pick one indentation style (spaces OR tabs) for line %d:\n", f.Line)
			fmt.Fprintf(b, "  Editorconfig: indent_style = space, indent_size = 2")
		}
	case "fmt-consecutive-blank-lines":
		fmt.Fprintf(b, "Collapse the consecutive blank lines at line %d to a single blank line:\n", f.Line)
		fmt.Fprintf(b, "  iris fmt %s --fix", filepath.Dir(f.File))
	case "fmt-gofmt":
		fmt.Fprintf(b, "Format the Go file with the standard formatter:\n")
		fmt.Fprintf(b, "  gofmt -w %s\n", f.File)
		fmt.Fprintf(b, "  or: iris fmt %s --fix  (or add `make fmt` to CI)", f.File)
	case "fmt-line-too-long":
		fmt.Fprintf(b, "Break line %d into multiple lines (<=120 chars), e.g. split the expression/string across lines:\n", f.Line)
		fmt.Fprintf(b, "  iris fmt %s --fix  (long lines are suggest-only, not auto-fixed)", filepath.Dir(f.File))
	default:
		fmt.Fprintf(b, "Auto-fix with: iris fmt %s --fix", filepath.Dir(f.File))
	}
}

func secretsFix(b *strings.Builder, f *Finding) {
	fmt.Fprintf(b, "1. Revoke/rotate this credential immediately in the provider console (it must be considered compromised).\n")
	fmt.Fprintf(b, "2. Remove the secret from %s and load it from the environment or a secret manager instead:\n", f.File)
	switch detectLanguage(f.File) {
	case "go":
		fmt.Fprintf(b, "     os.Getenv(\"%s_SECRET\") or os.LookupEnv\n", strings.ToUpper(f.RuleID))
	case "js", "ts":
		fmt.Fprintf(b, "     process.env.MY_SECRET (never hardcode; add to .env which is gitignored)\n")
	case "python":
		fmt.Fprintf(b, "     os.environ[\"MY_SECRET\"] or a .env file loaded via python-dotenv\n")
	default:
		fmt.Fprintf(b, "     export MY_SECRET=... in your environment/CI secrets\n")
	}
	fmt.Fprintf(b, "3. Purge it from git history (git filter-repo or BFG) — deletion alone keeps it in history.\n")
	fmt.Fprintf(b, "4. Add the pattern to .iris.yaml exclude or use a placeholder to prevent recurrence.")
}

func scaFix(b *strings.Builder, f *Finding) {
	fmt.Fprintf(b, "1. Identify the affected dependency and the fixed version from the advisory.\n")
	fmt.Fprintf(b, "2. Upgrade to the patched version:\n")
	switch detectManifest(filepath.Base(f.File)) {
	case "npm":
		fmt.Fprintf(b, "     npm update <pkg>   (or: npm install <pkg>@<fixed-version>)\n")
	case "pip":
		fmt.Fprintf(b, "     pip install -U <pkg> && pip freeze > requirements.txt\n")
	case "gomod":
		fmt.Fprintf(b, "     go get <pkg>@latest && go mod tidy\n")
	case "cargo":
		fmt.Fprintf(b, "     cargo update <pkg>\n")
	case "maven":
		fmt.Fprintf(b, "     bump <version> in pom.xml, then: mvn dependency:tree\n")
	default:
		fmt.Fprintf(b, "     update the lockfile/manifest %s\n", f.File)
	}
	fmt.Fprintf(b, "3. Re-run: iris scan . --scanner sca — and re-test the paths touching the dependency.\n")
	fmt.Fprintf(b, "4. If no fix exists: pin to a safe alternative, add mitigating controls, or exclude with a documented reason.")
}

func detectManifest(base string) string {
	switch strings.ToLower(base) {
	case "package-lock.json", "package.json", "yarn.lock", "pnpm-lock.yaml":
		return "npm"
	case "requirements.txt", "poetry.lock", "pipfile.lock":
		return "pip"
	case "go.mod", "go.sum":
		return "gomod"
	case "cargo.lock", "cargo.toml":
		return "cargo"
	case "pom.xml", "build.gradle":
		return "maven"
	case "composer.lock":
		return "composer"
	case "gemfile.lock":
		return "rubygems"
	default:
		return ""
	}
}

func sastFix(b *strings.Builder, f *Finding, lang string) {
	switch f.RuleID {
	case "sast-sql-injection", "sql-injection":
		fmt.Fprintf(b, "Use parameterized queries instead of string concatenation at %s:%d:\n", f.File, f.Line)
		switch lang {
		case "go":
			fmt.Fprintf(b, "  db.Query(\"SELECT ... WHERE id = $1\", id)   // instead of fmt.Sprintf\n")
		case "python":
			fmt.Fprintf(b, "  cursor.execute(\"SELECT ... WHERE id = %%s\", (id,))   // instead of f-strings\n")
		case "js", "ts":
			fmt.Fprintf(b, "  db.query('SELECT ... WHERE id = ?', [id])   // instead of template literals\n")
		default:
			fmt.Fprintf(b, "  Use prepared statements / bound parameters for every value.\n")
		}
		fmt.Fprintf(b, "Also validate IDs against an allowlist before querying.")
	case "sast-hardcoded-credentials", "hardcoded-credential":
		fmt.Fprintf(b, "Move the credential out of source into the environment:\n")
		fmt.Fprintf(b, "  1. Replace the literal with os.Getenv / process.env at %s:%d\n", f.File, f.Line)
		fmt.Fprintf(b, "  2. Inject the value via deployment secrets; rotate the exposed credential")
	case "sast-weak-crypto":
		fmt.Fprintf(b, "Replace the weak algorithm at %s:%d:\n", f.File, f.Line)
		switch lang {
		case "go":
			fmt.Fprintf(b, "  MD5/SHA1 → crypto/sha256; passwords → golang.org/x/crypto/bcrypt or argon2id\n")
		case "python":
			fmt.Fprintf(b, "  hashlib.md5() → hashlib.sha256(); passwords → bcrypt/argon2\n")
		default:
			fmt.Fprintf(b, "  Use SHA-256+ for hashes; bcrypt/argon2/scrypt for passwords; AES-GCM for encryption\n")
		}
	case "sast-path-traversal":
		fmt.Fprintf(b, "Validate and clean the user-controlled path at %s:%d before file access:\n", f.File, f.Line)
		if lang == "go" {
			fmt.Fprintf(b, "  filepath.Clean(p); ensure strings.HasPrefix(clean, filepath.Join(baseDir, \"\"))\n")
		} else {
			fmt.Fprintf(b, "  Normalize (.., /), then verify the resolved path stays inside the allowed base directory\n")
		}
	default:
		fmt.Fprintf(b, "Harden the flagged code at %s:%d:\n", f.File, f.Line)
		fmt.Fprintf(b, "  Validate/encode all inputs at the boundary, apply least-privilege defaults, and add a regression test for this exact pattern.\n")
		fmt.Fprintf(b, "  Details: iris explain %s", f.RuleID)
	}
}

func iacFix(b *strings.Builder, f *Finding) {
	switch {
	case strings.Contains(f.Title, "public") && strings.Contains(strings.ToLower(f.File), ".tf"):
		fmt.Fprintf(b, "Restrict the public exposure in %s:%d:\n", f.File, f.Line)
		fmt.Fprintf(b, "  1. Replace 0.0.0.0/0 in the ingress rule with specific CIDRs or security-group references\n")
		fmt.Fprintf(b, "  2. If the resource must stay public, front it with a load balancer/CDN and keep instances private")
	case strings.Contains(f.RuleID, "iac-"):
		fmt.Fprintf(b, "Fix the infrastructure definition at %s:%d:\n", f.File, f.Line)
		fmt.Fprintf(b, "  Apply least privilege, enable encryption, and pin versions per CIS benchmark.\n")
		fmt.Fprintf(b, "  Re-scan with: iris scan . --scanner iac")
	default:
		fmt.Fprintf(b, "Harden the definition at %s:%d per CIS benchmark, then re-scan with --scanner iac.", f.File, f.Line)
	}
}

func headerFix(b *strings.Builder, f *Finding) {
	title := strings.ToLower(f.Title)
	fmt.Fprintf(b, "Add/fix the header on the serving layer, then verify: curl -sI %s | grep -i %s\n", targetHint(f), headerName(f))
	switch {
	case strings.Contains(title, "hsts"):
		fmt.Fprintf(b, "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n")
		fmt.Fprintf(b, "  (Caddy: header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\")")
	case strings.Contains(title, "content-security") || strings.Contains(title, "csp"):
		fmt.Fprintf(b, "  Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'\n")
		fmt.Fprintf(b, "  Start with report-only to avoid breakage: Content-Security-Policy-Report-Only: ...")
	case strings.Contains(title, "x-frame-options") || strings.Contains(title, "clickjack"):
		fmt.Fprintf(b, "  X-Frame-Options: DENY  (or CSP: frame-ancestors 'none')\n")
		fmt.Fprintf(b, "  (Caddy: header X-Frame-Options \"DENY\")")
	case strings.Contains(title, "cors"):
		fmt.Fprintf(b, "  Restrict Access-Control-Allow-Origin to explicit trusted origins; drop the wildcard '*' with credentials.\n")
		fmt.Fprintf(b, "  Echo the Origin back only when it matches an allowlist.")
	case strings.Contains(title, "cookie"):
		fmt.Fprintf(b, "  Set-Cookie: ...; Secure; HttpOnly; SameSite=Lax  (strict for session cookies)")
	case strings.Contains(title, "server") || strings.Contains(title, "disclosure") || strings.Contains(title, "powered"):
		fmt.Fprintf(b, "  Suppress version banners:\n")
		fmt.Fprintf(b, "    Caddy: header -Server    Nginx: server_tokens off;    Express: app.disable('x-powered-by')")
	default:
		fmt.Fprintf(b, "  Set the recommended security header in your server/CDN config and re-run iris webscan.")
	}
}

func redirectFix(b *strings.Builder, f *Finding, lang string) {
	fmt.Fprintf(b, "Validate redirect targets at %s:%d before redirecting:\n", f.File, f.Line)
	switch lang {
	case "go":
		fmt.Fprintf(b, "  u, _ := url.Parse(target); if u.Host != \"\" && u.Host != allowedHost { http.Error(w, \"bad redirect\", 400) }\n")
	case "js", "ts":
		fmt.Fprintf(b, "  const u = new URL(target, base); if (u.origin !== allowedOrigin) throw new Error('bad redirect')\n")
	default:
		fmt.Fprintf(b, "  Only redirect to relative paths or an allowlist of hosts; never use raw user input as the destination.\n")
	}
}

func licenseFix(b *strings.Builder, f *Finding) {
	fmt.Fprintf(b, "Resolve the license conflict:\n")
	fmt.Fprintf(b, "  1. Review the license of the flagged package and your distribution model\n")
	fmt.Fprintf(b, "  2. Copyleft (GPL/AGPL) in a proprietary product → replace the package or get a commercial license\n")
	fmt.Fprintf(b, "  3. Acceptable? Add the package to the allowlist in .iris.yaml with a comment and owner")
}

func targetHint(f *Finding) string {
	if t := f.Metadata["target"]; t != nil {
		if s, ok := t.(string); ok {
			return s
		}
	}
	return "https://your-site.example"
}

func headerName(f *Finding) string {
	t := strings.ToLower(f.Title)
	switch {
	case strings.Contains(t, "hsts"):
		return "strict-transport"
	case strings.Contains(t, "content-security") || strings.Contains(t, "csp"):
		return "content-security"
	case strings.Contains(t, "frame"):
		return "x-frame"
	case strings.Contains(t, "cors"):
		return "access-control"
	case strings.Contains(t, "cookie"):
		return "set-cookie"
	default:
		return "server"
	}
}
