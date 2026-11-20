package core

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	rulesfs "github.com/Pixelcity-dev/Iris/rules"
	"gopkg.in/yaml.v3"
)

type Rule struct {
	ID          string   `json:"id" yaml:"id"`
	Name        string   `json:"name" yaml:"name"`
	Severity    Severity `json:"severity" yaml:"severity"`
	Category    string   `json:"category" yaml:"category"`
	Language    string   `json:"language,omitempty" yaml:"language,omitempty"`
	ScannerType ScanType `json:"scanner_type" yaml:"scanner_type"`
	Pattern     string   `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Description string   `json:"description" yaml:"description"`
	Fix         string   `json:"fix,omitempty" yaml:"fix,omitempty"`
	References  []string `json:"references,omitempty" yaml:"references,omitempty"`
	Tags        []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	Enabled     bool     `json:"enabled" yaml:"enabled"`
}

type RuleSet struct {
	Rules []Rule `json:"rules" yaml:"rules"`
}

type RuleEngine struct {
	rules     map[ScanType][]Rule
	overrides map[string]bool
	// index maps a rule ID to the scan type it was registered under, so a
	// later source (external rules) can override a built-in rule in place
	// instead of registering a duplicate that fires twice.
	index map[string]ScanType
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		rules:     make(map[ScanType][]Rule),
		overrides: make(map[string]bool),
		index:     make(map[string]ScanType),
	}
}

// LoadBuiltinRules loads the rule files embedded in the binary. This is what
// makes `iris scan` work from any directory, not just a checkout of the
// repository.
func (e *RuleEngine) LoadBuiltinRules() error {
	return e.LoadRulesFS(rulesfs.FS())
}

// LoadRulesFS walks an fs.FS and loads every YAML/JSON rule file it finds.
func (e *RuleEngine) LoadRulesFS(fsys fs.FS) error {
	return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		return e.loadRules(data, ext)
	})
}

func (e *RuleEngine) LoadRulesFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return e.loadRules(data, filepath.Ext(path))
}

func (e *RuleEngine) loadRules(data []byte, ext string) error {
	var ruleSet RuleSet

	switch strings.ToLower(ext) {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &ruleSet); err != nil {
			return err
		}
	case ".json":
		if err := json.Unmarshal(data, &ruleSet); err != nil {
			return err
		}
	default:
		return nil
	}

	for _, rule := range ruleSet.Rules {
		e.AddRule(rule)
	}

	return nil
}

func (e *RuleEngine) LoadRulesFromDir(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext == ".yaml" || ext == ".yml" || ext == ".json" {
			return e.LoadRulesFromFile(path)
		}
		return nil
	})
}

func (e *RuleEngine) AddRule(rule Rule) {
	if rule.ID == "" {
		return
	}
	if e.rules == nil {
		e.rules = make(map[ScanType][]Rule)
	}
	if e.index == nil {
		e.index = make(map[string]ScanType)
	}

	// A rule with the same ID from a later source (an external rules file)
	// replaces the built-in one instead of adding a duplicate finding.
	if prevType, ok := e.index[rule.ID]; ok {
		if prevType == rule.ScannerType {
			for i := range e.rules[prevType] {
				if e.rules[prevType][i].ID == rule.ID {
					e.rules[prevType][i] = rule
					return
				}
			}
		}
		// The rule moved to a different scanner: drop the old copy.
		rules := e.rules[prevType]
		for i := range rules {
			if rules[i].ID == rule.ID {
				e.rules[prevType] = append(rules[:i], rules[i+1:]...)
				break
			}
		}
	}

	e.rules[rule.ScannerType] = append(e.rules[rule.ScannerType], rule)
	e.index[rule.ID] = rule.ScannerType
}

func (e *RuleEngine) GetRulesForScanner(scanType ScanType) []Rule {
	rules := e.rules[scanType]
	var enabled []Rule
	for _, r := range rules {
		if r.Enabled && !e.overrides[r.ID] {
			enabled = append(enabled, r)
		}
	}
	return enabled
}

func (e *RuleEngine) GetAllRules() []Rule {
	var all []Rule
	for _, rules := range e.rules {
		all = append(all, rules...)
	}
	return all
}

func (e *RuleEngine) GetRuleByID(id string) *Rule {
	for _, rules := range e.rules {
		for _, r := range rules {
			if r.ID == id {
				return &r
			}
		}
	}
	return nil
}

func (e *RuleEngine) DisableRule(id string) {
	e.overrides[id] = true
}

func (e *RuleEngine) EnableRule(id string) {
	delete(e.overrides, id)
}

func (e *RuleEngine) SearchRules(query string) []Rule {
	query = strings.ToLower(query)
	var matches []Rule
	for _, rules := range e.rules {
		for _, r := range rules {
			if strings.Contains(strings.ToLower(r.Name), query) ||
				strings.Contains(strings.ToLower(r.Description), query) ||
				strings.Contains(strings.ToLower(r.ID), query) ||
				strings.Contains(strings.ToLower(r.Category), query) {
				matches = append(matches, r)
			}
			for _, tag := range r.Tags {
				if strings.Contains(strings.ToLower(tag), query) {
					matches = append(matches, r)
					break
				}
			}
		}
	}
	return matches
}

func (e *RuleEngine) GetRulesByLanguage(lang string) []Rule {
	var matches []Rule
	for _, rules := range e.rules {
		for _, r := range rules {
			if strings.EqualFold(r.Language, lang) || r.Language == "" {
				matches = append(matches, r)
			}
		}
	}
	return matches
}

func (e *RuleEngine) GetRulesByCategory(category string) []Rule {
	var matches []Rule
	for _, rules := range e.rules {
		for _, r := range rules {
			if strings.EqualFold(r.Category, category) {
				matches = append(matches, r)
			}
		}
	}
	return matches
}

func (e *RuleEngine) Stats() map[string]int {
	stats := make(map[string]int)
	for scanType, rules := range e.rules {
		stats[string(scanType)] = len(rules)
	}
	return stats
}
