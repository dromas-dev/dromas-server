package server

import (
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/dromas-dev/dromas-client/protocol"
)

// A message item's size is read only up to the protocol's largest
// ciphertext: a larger number is a broken item, never an int that wraps.
func TestAnItemsSizeIsBoundedByTheLargestCiphertext(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		n  string
		ok bool
	}{
		{"0", true},
		{strconv.Itoa(protocol.MaxCiphertext), true},
		{strconv.Itoa(protocol.MaxCiphertext + 1), false},
		{"18446744073709551615", false},
		{"-1", false},
	} {
		it := item{"size": &types.AttributeValueMemberN{Value: c.n}}
		got, err := it.size("size")
		if (err == nil) != c.ok {
			t.Errorf("size %s: %d, %v; want ok %v", c.n, got, err, c.ok)
		}
	}
}
