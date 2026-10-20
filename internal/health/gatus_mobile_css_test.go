package health

import (
	"os"
	"strings"
	"testing"
)

func TestPinnedGatusShortcutIsHiddenOnlyOnMobile(t *testing.T) {
	config, err := os.ReadFile("../../config/gatus.yaml")
	if err != nil {
		t.Fatal(err)
	}
	css := string(config)
	const rule = "@media (max-width: 840px) {\n      #social { display: none; }\n    }"
	if !strings.Contains(css, rule) {
		t.Fatalf("config does not hide the inspected Gatus #social wrapper at the mobile breakpoint")
	}
	if strings.Count(css, "#social") != 1 {
		t.Fatalf("expected exactly one verified #social selector, got %d", strings.Count(css, "#social"))
	}
	if strings.Index(css, rule) > strings.Index(css, "# Gatus requires") {
		t.Fatal("mobile shortcut rule must remain inside the custom CSS block")
	}
}
