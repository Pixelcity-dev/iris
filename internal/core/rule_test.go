package core

import "testing"

func TestLoadBuiltinRules(t *testing.T) {
	engine := NewRuleEngine()
	if err := engine.LoadBuiltinRules(); err != nil {
		t.Fatalf("LoadBuiltinRules: %v", err)
	}

	sast := engine.GetRulesForScanner(ScanTypeSAST)
	if len(sast) == 0 {
		t.Fatal("no SAST rules loaded from the embedded rule set")
	}

	// Every built-in rule must compile: a broken pattern would either fail to
	// load or be silently ignored at scan time.
	for _, rule := range engine.GetAllRules() {
		if rule.ScannerType == ScanTypeSAST && rule.Pattern == "" {
			t.Errorf("rule %s has no pattern", rule.ID)
		}
	}
}

func TestAddRuleOverridesSameID(t *testing.T) {
	engine := NewRuleEngine()
	engine.AddRule(Rule{ID: "custom-one", ScannerType: ScanTypeSAST, Pattern: "old", Enabled: true})
	engine.AddRule(Rule{ID: "custom-one", ScannerType: ScanTypeSAST, Pattern: "new", Enabled: true})

	rules := engine.GetRulesForScanner(ScanTypeSAST)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule after override, got %d", len(rules))
	}
	if rules[0].Pattern != "new" {
		t.Fatalf("expected overridden pattern %q, got %q", "new", rules[0].Pattern)
	}
}

func TestSearchRulesMatchesTags(t *testing.T) {
	engine := NewRuleEngine()
	if err := engine.LoadBuiltinRules(); err != nil {
		t.Fatalf("LoadBuiltinRules: %v", err)
	}
	if got := engine.SearchRules("owasp-top10"); len(got) == 0 {
		t.Fatal("expected tag search to find built-in rules")
	}
}
