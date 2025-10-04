package longspurio

import "testing"

func Test_OneEntryRelFs_RelativePath(t *testing.T) {
	tests := []struct {
		parent string
		child  string
		err    bool
	}{
		{
			parent: "a/b/c",
			child:  ".",
			err:    false,
		},
		{
			parent: "a/b/c",
			child:  "c",
			err:    true,
		},
		{
			parent: "a/b/c",
			child:  "a/b/c",
			err:    true,
		},
		{
			parent: "a/b/c",
			child:  "../c",
			err:    false,
		},
		{
			parent: "a/b/c",
			child:  "../../../a/b/c",
			err:    false,
		},
		{
			parent: "a/b/c",
			child:  "../../../../../1/2/a/b/c",
			err:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.parent+"-"+tt.child, func(t *testing.T) {
			fs := NewOneEntryRelFs(tt.parent, []byte{})
			got, err := fs.RelativePath(tt.parent, tt.child)
			if err != nil {
				if !tt.err {
					t.Fatalf("unexpected error: %v", err)
				}
			} else if tt.err {
				t.Fatalf("expected error, got none")
			} else if got != tt.parent {
				t.Errorf("expected %q, got %q", tt.parent, got)
			}
		})
	}
}
