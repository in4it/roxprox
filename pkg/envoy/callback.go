package envoy

import (
	"context"

	v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
)

type Callback struct {
	waitForEnvoy chan struct{}
	newNode      chan NewNode
	connections  map[int64]*core.Node
}
type NewNode struct {
	id string
}

func newCallback() *Callback {
	waitForEnvoy := make(chan struct{})
	newNode := make(chan NewNode)
	return &Callback{
		waitForEnvoy: waitForEnvoy,
		newNode:      newNode,
		connections:  make(map[int64]*core.Node),
	}
}
func (c *Callback) OnStreamOpen(ctx context.Context, id int64, typ string) error {
	logger.Tracef("OnStreamOpen %d open for %s", id, typ)
	return nil
}
func (c *Callback) OnStreamClosed(id int64) {
	logger.Tracef("OnStreamClosed %d closed", id)
}
func (c *Callback) OnStreamRequest(id int64, req *v2.DiscoveryRequest) error {
	logger.Tracef("OnStreamRequest: %d %+v", id, req)
	if _, ok := c.connections[id]; !ok {
		c.connections[id] = req.Node
		c.newNode <- NewNode{id: req.Node.Id}
	}
	if c.waitForEnvoy != nil {
		close(c.waitForEnvoy)
		c.waitForEnvoy = nil
	}
	return nil
}
func (c *Callback) OnFetchRequest(ctx context.Context, req *v2.DiscoveryRequest) error {
	logger.Tracef("OnFetchRequest...")
	if c.waitForEnvoy != nil {
		close(c.waitForEnvoy)
		c.waitForEnvoy = nil
	}
	return nil
}
func (c *Callback) OnStreamResponse(int64, *v2.DiscoveryRequest, *v2.DiscoveryResponse) {}

func (c *Callback) OnFetchResponse(*v2.DiscoveryRequest, *v2.DiscoveryResponse) {}
