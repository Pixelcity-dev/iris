// Package rules ships the built-in detection rules inside the Iris binary.
//
// The same YAML files can be inspected and edited on disk, but a released
// binary must not depend on them: an installed iris is run from arbitrary
// directories where a relative "rules" directory does not exist. Embedding
// keeps the scanners working offline and outside the repository, while
// external rule files still override built-ins by ID.
package rules

import (
	"embed"
	"io/fs"
)

//go:embed builtin
var builtin embed.FS

// FS returns the embedded rule tree, rooted at the builtin/ directory.
func FS() fs.FS {
	sub, err := fs.Sub(builtin, "builtin")
	if err != nil {
		// The embed directive guarantees this directory exists.
		panic("rules: embedded builtin tree missing: " + err.Error())
	}
	return sub
}
