package json

import (
	"strings"
	"testing"
)

func TestNoctweaveJSONDepthLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		depth int
		valid bool
	}{
		{name: "at limit", depth: maxNestingDepth, valid: true},
		{name: "above limit", depth: maxNestingDepth + 1, valid: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(strings.Repeat("[", tc.depth) + "0" + strings.Repeat("]", tc.depth))
			var scan scanner
			err := checkValid(input, &scan)
			if tc.valid && err != nil {
				t.Fatalf("valid nesting rejected: %v", err)
			}
			if !tc.valid && (err == nil || !strings.Contains(err.Error(), "exceeded max depth")) {
				t.Fatalf("excessive nesting accepted or rejected for the wrong reason: %v", err)
			}
		})
	}
}
