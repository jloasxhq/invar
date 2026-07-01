package dlt

import (
	"errors"
	"testing"
)

func TestStubReturnsNotImplemented(t *testing.T) {
	a := NewFabricAdapter("mychannel", "cannabux-cc")
	if _, err := a.TotalSupply(); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented, got %v", err)
	}
	if a.ChannelID != "mychannel" || a.ChaincodeName != "cannabux-cc" {
		t.Fatalf("adapter fields not set")
	}
}
