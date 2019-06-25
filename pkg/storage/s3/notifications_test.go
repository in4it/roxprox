package s3

import (
	"testing"
	"fmt"
)
func TestLookupPeers(t *testing.T) {
	config := Config{
		Bucket: "bucket",
	}
	n := newNotifications(config)
	peers := n.lookupPeers()
	fmt.Printf("%+v", peers)
	if len(peers) == 0 {
		t.Errorf("No peers returned")
	}
}