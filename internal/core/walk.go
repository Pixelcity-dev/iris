package core

import (
	"path"
	"path/filepath"
	"strings"
)

// skippedDirNames are directories that never contain first-party source.
// Walking them wastes time and floods reports with findings in dependencies
// and build output, so every filesystem scanner skips them by default.
var skippedDirNames = map[string]bool{
	".git":         true,
	".hg":          true,
	".svn":         true,
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	"bin":          true,
	".next":        true,
	".nuxt":        true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	".iris":        true,
	".idea":        true,
	".gradle":      true,
	"target":       true,
}

// ShouldSkipDir reports whether a filesystem scanner should skip this
// directory entirely.
func ShouldSkipDir(name string) bool {
	return skippedDirNames[name]
}

// MaxScanFileBytes caps how much of a single file a scanner reads. Generated
// bundles and vendored blobs are not useful to pattern scanners and only slow
// them down.
const MaxScanFileBytes = 2 << 20 // 2 MiB

// MatchFilePatterns reports whether file matches any of the glob patterns.
// Patterns are matched against the slash-separated path and its base name.
// `**` matches any number of path segments, so "--exclude 'testdata/**'" and
// "--exclude '**/*_test.go'" behave the way people expect.
func MatchFilePatterns(file string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	normalized := filepath.ToSlash(file)
	base := path.Base(normalized)
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(filepath.ToSlash(pattern))
		if pattern == "" {
			continue
		}
		if matchGlob(pattern, normalized) {
			return true
		}
		if !strings.Contains(pattern, "/") {
			if ok, _ := path.Match(pattern, base); ok {
				return true
			}
		}
		// A directory pattern such as "vendor" should match everything below it.
		trimmed := strings.TrimSuffix(pattern, "/")
		if !strings.Contains(trimmed, "*") && trimmed != "" &&
			(normalized == trimmed || strings.HasPrefix(normalized, trimmed+"/")) {
			return true
		}
	}
	return false
}

// matchGlob matches a slash-separated glob against a path, with ** spanning
// whole segments.
func matchGlob(pattern, name string) bool {
	return matchSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func matchSegments(pattern, name []string) bool {
	if len(pattern) == 0 {
		return len(name) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(name); i++ {
			if matchSegments(pattern[1:], name[i:]) {
				return true
			}
		}
		return false
	}
	if len(name) == 0 {
		return false
	}
	ok, err := path.Match(pattern[0], name[0])
	if err != nil || !ok {
		return false
	}
	return matchSegments(pattern[1:], name[1:])
}
