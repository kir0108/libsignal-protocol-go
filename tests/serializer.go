package tests

import (
	"github.com/kir0108/libsignal-protocol-go/serialize"
)

// newSerializer will return a JSON serializer for testing.
func newSerializer() *serialize.Serializer {
	serializer := serialize.NewJSONSerializer()

	return serializer
}
