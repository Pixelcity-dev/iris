package format

import "testing"

func TestFixedContentCollapsesBlankRuns(t *testing.T) {
	input := "one\n\n\n\ntwo\n\nthree\n"
	want := "one\n\ntwo\n\nthree\n"
	if got := FixedContent("notes.txt", input); got != want {
		t.Fatalf("FixedContent:\n got %q\nwant %q", got, want)
	}
}

func TestFixedContentTrimsWhitespaceAndEndsWithNewline(t *testing.T) {
	input := "alpha   \nbeta\t\n\ngamma"
	want := "alpha\nbeta\n\ngamma\n"
	if got := FixedContent("notes.txt", input); got != want {
		t.Fatalf("FixedContent:\n got %q\nwant %q", got, want)
	}
}

func TestFixedContentNormalizesCRLF(t *testing.T) {
	input := "a\r\nb\r\n"
	want := "a\nb\n"
	if got := FixedContent("notes.txt", input); got != want {
		t.Fatalf("FixedContent:\n got %q\nwant %q", got, want)
	}
}

func TestIsSupported(t *testing.T) {
	if !IsSupported("main.go") || !IsSupported("Dockerfile") {
		t.Error("expected Go and Dockerfile to be supported")
	}
	if IsSupported("image.png") {
		t.Error("binary assets should not be formatted")
	}
}
