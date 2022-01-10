package envoy

import (
	"context"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
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
func (c *Callback) OnDeltaStreamOpen(ctx context.Context, id int64, typ string) error {
	logger.Tracef("OnDeltaStreamOpen %d open for %s", id, typ)
	return nil
}

func (c *Callback) OnStreamClosed(id int64) {
	logger.Tracef("OnStreamClosed %d closed", id)
}
func (c *Callback) OnDeltaStreamClosed(id int64) {
	logger.Tracef("OnDeltaStreamClosed %d closed", id)

}
func (c *Callback) OnStreamRequest(id int64, req *discovery.DiscoveryRequest) error {
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
func (c *Callback) OnStreamDeltaRequest(id int64, req *discovery.DeltaDiscoveryRequest) error {
	logger.Tracef("OnStreamDeltaRequest: %d %+v", id, req)
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
func (c *Callback) OnFetchRequest(ctx context.Context, req *discovery.DiscoveryRequest) error {
	logger.Tracef("OnFetchRequest...")
	if c.waitForEnvoy != nil {
		close(c.waitForEnvoy)
		c.waitForEnvoy = nil
	}
	return nil
}
func (c *Callback) OnStreamResponse(context.Context, int64, *discovery.DiscoveryRequest, *discovery.DiscoveryResponse) {
}
func (c *Callback) OnStreamDeltaResponse(id int64, req *discovery.DeltaDiscoveryRequest, res *discovery.DeltaDiscoveryResponse) {
}

func (c *Callback) OnFetchResponse(*discovery.DiscoveryRequest, *discovery.DiscoveryResponse) {}
