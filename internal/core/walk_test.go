package core

import "testing"

func TestShouldSkipDir(t *testing.T) {
	for _, name := range []string{".git", "node_modules", "vendor", "dist"} {
		if !ShouldSkipDir(name) {
			t.Errorf("expected %q to be skipped", name)
		}
	}
	if ShouldSkipDir("internal") {
		t.Error("first-party directory should not be skipped")
	}
}

func TestMatchFilePatterns(t *testing.T) {
	tests := []struct {
		file     string
		patterns []string
		want     bool
	}{
		{"src/app.min.js", []string{"*.min.js"}, true},
		{"src/app.js", []string{"*.min.js"}, false},
		{"vendor/lib/x.go", []string{"vendor"}, true},
		{"internal/app/x.go", []string{"vendor"}, false},
		{"tests/fixtures/key.pem", []string{"tests/**"}, true},
		{"src/a/b/gen.go", []string{"**/gen.go"}, true},
		{"src/a/b/main.go", []string{"**/gen.go"}, false},
		{"docs/readme.md", []string{"docs/*"}, true},
		{"main.go", nil, false},
	}
	for _, tt := range tests {
		if got := MatchFilePatterns(tt.file, tt.patterns); got != tt.want {
			t.Errorf("MatchFilePatterns(%q, %v) = %v, want %v", tt.file, tt.patterns, got, tt.want)
		}
	}
}
