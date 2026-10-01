package findings

import (
	"encoding/json"
	"testing"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		in      string
		want    Severity
		wantErr bool
	}{
		{"critical", SeverityCritical, false},
		{"HIGH", SeverityHigh, false},
		{" medium ", SeverityMedium, false},
		{"low", SeverityLow, false},
		{"info", SeverityInfo, false},
		{"", SeverityUnknown, true},
		{"severe", SeverityUnknown, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseSeverity(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseSeverity(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("ParseSeverity(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestSeverityOrderingAndLabels(t *testing.T) {
	ordered := AllSeverities()
	for i := 1; i < len(ordered); i++ {
		if !ordered[i-1].AtLeast(ordered[i]) || ordered[i].AtLeast(ordered[i-1]) {
			t.Fatalf("severities not strictly ordered: %v vs %v", ordered[i-1], ordered[i])
		}
	}
	if SeverityHigh.Label() != "HIGH" {
		t.Fatalf("Label() = %q", SeverityHigh.Label())
	}
	if SeverityUnknown.String() != "unknown" || SeverityUnknown.Valid() {
		t.Fatal("unknown severity must not be valid")
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	for _, sev := range AllSeverities() {
		data, err := json.Marshal(sev)
		if err != nil {
			t.Fatal(err)
		}
		var back Severity
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatal(err)
		}
		if back != sev {
			t.Fatalf("round trip %v -> %s -> %v", sev, data, back)
		}
	}
	if _, err := json.Marshal(SeverityUnknown); err == nil {
		t.Fatal("expected error when marshaling unknown severity")
	}
	var s Severity
	if err := json.Unmarshal([]byte(`"bogus"`), &s); err == nil {
		t.Fatal("expected error for bogus severity")
	}
	if err := json.Unmarshal([]byte(`42`), &s); err == nil {
		t.Fatal("expected error for non-string severity")
	}
}

func TestConfidenceRank(t *testing.T) {
	if ConfidenceHigh.Rank() <= ConfidenceMedium.Rank() || ConfidenceMedium.Rank() <= ConfidenceLow.Rank() || ConfidenceLow.Rank() <= Confidence("").Rank() {
		t.Fatal("confidence ranks are not ordered")
	}
}

func TestCategoriesValid(t *testing.T) {
	for _, c := range Categories() {
		if !c.Valid() {
			t.Fatalf("category %q should be valid", c)
		}
	}
	if Category("config").Valid() {
		t.Fatal("unexpected valid category")
	}
}

func TestCounts(t *testing.T) {
	list := []Finding{
		{Severity: SeverityCritical}, {Severity: SeverityHigh}, {Severity: SeverityHigh},
		{Severity: SeverityMedium}, {Severity: SeverityLow}, {Severity: SeverityInfo},
	}
	c := Count(list)
	if c.Total() != 6 || c.Critical != 1 || c.High != 2 || c.Medium != 1 || c.Low != 1 || c.Info != 1 {
		t.Fatalf("unexpected counts %+v", c)
	}
	tests := []struct {
		threshold Severity
		want      int
	}{
		{SeverityCritical, 1}, {SeverityHigh, 3}, {SeverityMedium, 4}, {SeverityLow, 5}, {SeverityInfo, 6},
	}
	for _, tt := range tests {
		if got := c.AtLeast(tt.threshold); got != tt.want {
			t.Errorf("AtLeast(%v) = %d, want %d", tt.threshold, got, tt.want)
		}
	}
	if c.Get(SeverityUnknown) != 0 {
		t.Fatal("unknown severity must count as zero")
	}
}

func TestSortIsDeterministic(t *testing.T) {
	mk := func(sev Severity, rule, target string, line int, ev string) Finding {
		var loc *Location
		if line > 0 {
			loc = &Location{File: "c.yml", Line: line}
		}
		return Finding{Severity: sev, RuleID: rule, TargetName: target, Location: loc, Evidence: []string{ev}, ID: rule + target + ev}
	}
	input := []Finding{
		mk(SeverityLow, "SST-SEC-009", "web", 0, "a"),
		mk(SeverityCritical, "SST-SEC-002", "db", 0, "a"),
		mk(SeverityHigh, "SST-SEC-003", "web", 0, "a"),
		mk(SeverityCritical, "SST-SEC-001", "web", 0, "a"),
		mk(SeverityCritical, "SST-SEC-001", "app", 12, "b"),
		mk(SeverityCritical, "SST-SEC-001", "app", 9, "b"),
		mk(SeverityCritical, "SST-SEC-001", "app", 9, "a"),
		mk(SeverityCritical, "SST-SEC-001", "app", 0, "z"),
	}
	want := []string{
		"SST-SEC-001app z", "SST-SEC-001app a", "SST-SEC-001app b", "SST-SEC-001app b",
		"SST-SEC-001web a", "SST-SEC-002db a", "SST-SEC-003web a", "SST-SEC-009web a",
	}
	for round := 0; round < 3; round++ {
		list := append([]Finding(nil), input...)
		if round == 1 {
			for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
				list[i], list[j] = list[j], list[i]
			}
		}
		Sort(list)
		for i, f := range list {
			got := f.RuleID + f.TargetName + " " + f.Evidence[0]
			if got != want[i] {
				t.Fatalf("round %d position %d = %q, want %q", round, i, got, want[i])
			}
		}
		if list[2].Location.Line != 9 || list[3].Location.Line != 12 {
			t.Fatalf("locations should sort numerically, got %d then %d", list[2].Location.Line, list[3].Location.Line)
		}
	}
}

func TestFilterMinSeverity(t *testing.T) {
	list := []Finding{{Severity: SeverityHigh}, {Severity: SeverityLow}, {Severity: SeverityCritical}}
	got := FilterMinSeverity(list, SeverityHigh)
	if len(got) != 2 || got[0].Severity != SeverityHigh || got[1].Severity != SeverityCritical {
		t.Fatalf("unexpected filter result %+v", got)
	}
}

func TestFingerprintStableAndDistinct(t *testing.T) {
	a := Fingerprint("SST-SEC-001", TargetService, "web", []string{"x"})
	b := Fingerprint("SST-SEC-001", TargetService, "web", []string{"x"})
	c := Fingerprint("SST-SEC-001", TargetService, "web", []string{"y"})
	d := Fingerprint("SST-SEC-001", TargetService, "webx", nil)
	if a != b {
		t.Fatal("fingerprint is not stable")
	}
	if a == c || a == d || len(a) != 16 {
		t.Fatalf("fingerprints should differ and be 16 chars: %s %s %s", a, c, d)
	}
}

func TestLocationString(t *testing.T) {
	var nilLoc *Location
	if nilLoc.String() != "" {
		t.Fatal("nil location should render empty")
	}
	if (&Location{File: "a.yml"}).String() != "a.yml" {
		t.Fatal("file only")
	}
	if (&Location{File: "a.yml", Line: 3}).String() != "a.yml:3" {
		t.Fatal("file and line")
	}
}
