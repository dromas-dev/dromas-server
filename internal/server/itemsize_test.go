package server

import (
	"math"
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

// A stored time in milliseconds is read only up to the largest int64: a
// larger number is a broken item or key, never a time that wraps.
func TestATimeInMillisecondsIsBoundedByTheLargestInt64(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		n  string
		ok bool
	}{
		{"0", true},
		{strconv.FormatUint(math.MaxInt64, 10), true},
		{strconv.FormatUint(math.MaxInt64+1, 10), false},
		{"18446744073709551615", false},
		{"-1", false},
	} {
		it := item{"created": &types.AttributeValueMemberN{Value: c.n}}
		got, err := it.millis("created")
		if (err == nil) != c.ok {
			t.Errorf("created %s: %v, %v; want ok %v", c.n, got, err, c.ok)
		}
	}
}

// A stored time in seconds, a TTL attribute's, is read only up to the
// largest int64: a larger number is a broken item, never a time that wraps.
func TestATimeInSecondsIsBoundedByTheLargestInt64(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		n  string
		ok bool
	}{
		{"0", true},
		{strconv.FormatUint(math.MaxInt64, 10), true},
		{strconv.FormatUint(math.MaxInt64+1, 10), false},
		{"18446744073709551615", false},
	} {
		it := item{"expires_at": &types.AttributeValueMemberN{Value: c.n}}
		got, err := it.seconds("expires_at")
		if (err == nil) != c.ok {
			t.Errorf("expires_at %s: %v, %v; want ok %v", c.n, got, err, c.ok)
		}
	}
}

// A stored count is read only up to the largest int32, so it is an int on
// every platform: a larger number is a broken item, never an int that wraps.
func TestACountIsBoundedByTheLargestInt32(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		n  string
		ok bool
	}{
		{"0", true},
		{strconv.Itoa(math.MaxInt32), true},
		{strconv.Itoa(math.MaxInt32 + 1), false},
		{"18446744073709551615", false},
	} {
		it := item{"uses": &types.AttributeValueMemberN{Value: c.n}}
		got, err := it.count("uses")
		if (err == nil) != c.ok {
			t.Errorf("uses %s: %d, %v; want ok %v", c.n, got, err, c.ok)
		}
	}
}
