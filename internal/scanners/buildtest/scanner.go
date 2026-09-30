package buildtest

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

// BuildTestScanner analyzes the project's language and structure, runs the
// matching build/test toolchain, and reports build & test failures as findings.
type BuildTestScanner struct {
	core.BaseScanner
	name      string
	skipBuild bool
	skipTests bool
}

func NewBuildTestScanner() *BuildTestScanner {
	return &BuildTestScanner{
		BaseScanner: core.BaseScanner{Enabled: true},
		name:        "buildtest",
	}
}

// SetOptions allows the CLI to control which steps are executed.
func (s *BuildTestScanner) SetOptions(skipBuild, skipTests bool) {
	s.skipBuild = skipBuild
	s.skipTests = skipTests
}

func (s *BuildTestScanner) Name() string        { return s.name }
func (s *BuildTestScanner) Type() core.ScanType { return core.ScanTypeBuildTest }

func (s *BuildTestScanner) SupportedTargets() []core.TargetKind {
	return []core.TargetKind{core.TargetFS, core.TargetRepo}
}

// toolchain describes a detected language and its standard build/test commands.
type toolchain struct {
	Name     string
	Manifest string
	Build    []string
	Test     []string
}

// languageMarkers maps manifest files to toolchains. Commands are the
// standard zero-config build/test invocations for each ecosystem.
func languageMarkers() map[string]toolchain {
	return map[string]toolchain{
		"go.mod": {
			Name: "Go", Manifest: "go.mod",
			Build: []string{"go", "build", "./..."},
			Test:  []string{"go", "test", "./..."},
		},
		"package.json": {
			Name: "Node.js", Manifest: "package.json",
			Build: []string{"npm", "run", "build"},
			Test:  []string{"npm", "test", "--silent"},
		},
		"Cargo.toml": {
			Name: "Rust", Manifest: "Cargo.toml",
			Build: []string{"cargo", "build"},
			Test:  []string{"cargo", "test"},
		},
		"pom.xml": {
			Name: "Java (Maven)", Manifest: "pom.xml",
			Build: []string{"mvn", "-q", "compile"},
			Test:  []string{"mvn", "-q", "test"},
		},
		"build.gradle": {
			Name: "Java (Gradle)", Manifest: "build.gradle",
			Build: []string{"gradle", "build", "-x", "test"},
			Test:  []string{"gradle", "test"},
		},
		"pyproject.toml": {
			Name: "Python", Manifest: "pyproject.toml",
			Build: []string{"python", "-m", "compileall", "-q", "."},
			Test:  []string{"python", "-m", "pytest", "-q"},
		},
		"requirements.txt": {
			Name: "Python", Manifest: "requirements.txt",
			Build: []string{"python", "-m", "compileall", "-q", "."},
			Test:  []string{"python", "-m", "pytest", "-q"},
		},
	}
}

func (s *BuildTestScanner) Scan(ctx context.Context, target core.Target, rules []core.Rule) ([]core.Finding, error) {
	root := target.URI
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("buildtest target not found: %s", root)
	}
	if !info.IsDir() {
		root = filepath.Dir(root)
	}

	var findings []core.Finding

	toolchains := detectToolchains(root)
	if len(toolchains) == 0 {
		findings = append(findings, core.Finding{
			RuleID:      "buildtest-no-toolchain",
			Severity:    core.SeverityInfo,
			Category:    "build",
			Title:       "No build toolchain detected",
			Description: "No recognized language manifest (go.mod, package.json, Cargo.toml, pom.xml, …) was found; automated build tests were skipped.",
			Fix:         "Add a manifest for your toolchain (go.mod, package.json, Cargo.toml, pom.xml, build.gradle, pyproject.toml …) or run iris scan --scanner sast instead.",
			Confidence:  1.0,
		})
		return findings, nil
	}

	for _, tc := range toolchains {
		if !commandAvailable(tc.Build[0]) {
			findings = append(findings, core.Finding{
				RuleID:      "buildtest-toolchain-missing",
				Severity:    core.SeverityMedium,
				Category:    "build",
				Title:       fmt.Sprintf("%s toolchain not installed", tc.Name),
				Description: fmt.Sprintf("%s is detected via %s, but '%s' was not found in PATH; build tests cannot run.", tc.Name, tc.Manifest, tc.Build[0]),
				File:        filepath.Join(root, tc.Manifest),
				Fix:         fmt.Sprintf("Install the %s toolchain and ensure '%s' is on PATH, or disable the buildtest scanner in .iris.yaml.", tc.Name, tc.Build[0]),
				Confidence:  1.0,
			})
			continue
		}

		if !s.skipBuild {
			findings = append(findings, s.runStep(ctx, root, tc, stepBuild)...)
		}
		if !s.skipTests {
			findings = append(findings, compileErrorsToFindings(s.runStep(ctx, root, tc, stepTest)...)...)
		}
	}

	return findings, nil
}

type stepKind int

const (
	stepBuild stepKind = iota
	stepTest
)

func (s *BuildTestScanner) runStep(ctx context.Context, root string, tc toolchain, kind stepKind) []core.Finding {
	var cmdArgs []string
	var label string
	switch kind {
	case stepBuild:
		cmdArgs = tc.Build
		label = "build"
	default:
		cmdArgs = tc.Test
		label = "test"
	}
	if len(cmdArgs) == 0 {
		return nil
	}

	start := time.Now()
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CI=true", "GOFLAGS=-mod=mod")
	out, runErr := combinedOutputCapped(cmd, 256*1024)
	dur := time.Since(start)

	if runErr != nil {
		return []core.Finding{{
			RuleID:      "buildtest-" + label + "-failed",
			Severity:    core.SeverityHigh,
			Category:    "build",
			Title:       fmt.Sprintf("%s %s failed", tc.Name, label),
			Description: firstLines(out, 12),
			File:        filepath.Join(root, tc.Manifest),
			Metadata: map[string]interface{}{
				"command":  strings.Join(cmdArgs, " "),
				"output":   out,
				"exit":     exitCode(runErr),
				"duration": dur.String(),
			},
			Fix:        buildFixSuggestion(tc, label),
			Confidence: 1.0,
		}}
	}

	// Successful runs may still surface warnings (INFO level).
	return warnFindings(tc, label, out)
}

func combinedOutputCapped(cmd *exec.Cmd, maxBytes int) (string, error) {
	pr, pw, _ := os.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	runErr := cmd.Run()
	_ = pw.Close()
	var sb strings.Builder
	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() && sb.Len() < maxBytes {
		sb.WriteString(sc.Text())
		sb.WriteString("\n")
	}
	_ = pr.Close()
	return sb.String(), runErr
}

func exitCode(err error) string {
	if err == nil {
		return "0"
	}
	var ee *exec.ExitError
	if ok := asExitError(err, &ee); ok && ee != nil {
		return strconv.Itoa(ee.ExitCode())
	}
	return "n/a"
}

func asExitError(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// compileErrorsToFindings promotes compiler/test error lines from a failed
// test run into individual, per-location findings.
func compileErrorsToFindings(findings ...core.Finding) []core.Finding {
	var out []core.Finding
	for _, f := range findings {
		out = append(out, f)
		if f.RuleID != "buildtest-test-failed" && f.RuleID != "buildtest-build-failed" {
			continue
		}
		output, _ := f.Metadata["output"].(string)
		limit := 25
		for _, line := range strings.Split(output, "\n") {
			if limit <= 0 {
				break
			}
			if fl := parseDiagnostic(line); fl != nil {
				fl.RuleID = "buildtest-compile-error"
				fl.Category = "build"
				fl.Confidence = 0.95
				out = append(out, *fl)
				limit--
			}
		}
	}
	return out
}

var diagRe = regexp.MustCompile(`^([^:\s]+\.(?:go|ts|tsx|js|jsx|py|rs|java|kt|cs|c|cpp|h)):(\d+)(?::(\d+))?:\s*(error|warning|Error|SyntaxError)?[:\s]*(.*)$`)

func parseDiagnostic(line string) *core.Finding {
	m := diagRe.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return nil
	}
	kind := m[4]
	msg := strings.TrimSpace(m[5])
	if strings.EqualFold(kind, "warning") || msg == "" {
		return nil
	}
	lineNo, _ := strconv.Atoi(m[2])
	f := &core.Finding{
		Severity:    core.SeverityHigh,
		Title:       "Compile error: " + truncateMsg(msg, 120),
		Description: strings.TrimSpace(line),
		File:        m[1],
		Line:        lineNo,
	}
	if m[3] != "" {
		col, _ := strconv.Atoi(m[3])
		f.Column = col
	}
	return f
}

func truncateMsg(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func warnFindings(tc toolchain, label, out string) []core.Finding {
	var findings []core.Finding
	limit := 10
	for _, line := range strings.Split(out, "\n") {
		if limit <= 0 {
			break
		}
		l := strings.TrimSpace(line)
		if l == "" || !strings.Contains(strings.ToLower(l), "warning") {
			continue
		}
		if strings.Contains(l, "0 warnings") || strings.Contains(l, "no warnings") {
			continue
		}
		findings = append(findings, core.Finding{
			RuleID:      "buildtest-warning",
			Severity:    core.SeverityInfo,
			Category:    "build",
			Title:       fmt.Sprintf("%s %s warning", tc.Name, label),
			Description: truncateMsg(l, 200),
			Fix:         "Review the warning above; most toolchains can escalate warnings (e.g. go vet, tsc --noUnusedLocals) to catch these earlier.",
			Confidence:  0.5,
		})
		limit--
	}
	return findings
}

func buildFixSuggestion(tc toolchain, label string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "1. Reproduce locally: cd <project-root> && %s\n", strings.Join(stepCmd(tc, label), " "))
	switch tc.Name {
	case "Go":
		fmt.Fprintf(&b, "2. Fix the FIRST reported error — later ones are usually fallout.\n")
		fmt.Fprintf(&b, "3. Missing/unused dependency? Run `go mod tidy` and rebuild.\n")
		fmt.Fprintf(&b, "4. Type errors: read file:line from the finding above; `go vet ./...` catches related issues.")
	case "Node.js":
		fmt.Fprintf(&b, "2. TypeScript errors: fix the first, re-run — cascades are common.\n")
		fmt.Fprintf(&b, "3. Missing module? `npm install`. Lockfile drift in CI? Use `npm ci`.")
	case "Rust":
		fmt.Fprintf(&b, "2. Apply the compiler's `help:` suggestion — rustc hints are usually exact.\n")
		fmt.Fprintf(&b, "3. `cargo check` is faster than build while iterating.")
	case "Python":
		fmt.Fprintf(&b, "2. SyntaxError → fix file:line; failed tests → run the single test: python -m pytest <file>::<test> -x.")
	default:
		fmt.Fprintf(&b, "2. Fix the first reported error at the listed file:line, then re-run the build.")
	}
	return b.String()
}

func stepCmd(tc toolchain, label string) []string {
	if label == "build" {
		return tc.Build
	}
	return tc.Test
}

func commandAvailable(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// detectToolchains finds manifests in the root and one level deep (monorepos).
func detectToolchains(root string) []toolchain {
	var tcs []toolchain
	seen := map[string]bool{}
	add := func(tc toolchain) {
		if !seen[tc.Name] {
			seen[tc.Name] = true
			tcs = append(tcs, tc)
		}
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	markers := languageMarkers()
	for _, e := range entries {
		if tc, ok := markers[e.Name()]; ok {
			add(tc)
		}
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		sub, err := os.ReadDir(filepath.Join(root, e.Name()))
		if err != nil {
			continue
		}
		for _, se := range sub {
			if tc, ok := markers[se.Name()]; ok {
				add(tc)
			}
		}
	}
	return tcs
}
