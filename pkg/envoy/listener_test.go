package envoy

import (
	"testing"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
)

func TestDomainAlreadyExists(t *testing.T) {
	l := newListener()
	var cache WorkQueueCache
	params1 := ListenerParams{
		Name:           "test_1",
		Protocol:       "http",
		TargetHostname: "www.test.inv",
		Conditions: Conditions{
			Hostname: "hostname1.example.com",
			Prefix:   "/test1",
		},
	}
	params2 := ListenerParams{
		Name:           "test_2",
		Protocol:       "http",
		TargetHostname: "www.test.inv",
		Conditions: Conditions{
			Hostname: "hostname1.example.com",
			Prefix:   "/test2",
		},
	}
	paramsTLS1 := TLSParams{}
	listener := l.createListener(params1, paramsTLS1)
	cache.listeners = append(cache.listeners, listener)
	err := l.updateListener(&cache, params2, paramsTLS1)
	if err == nil {
		t.Errorf("Should have gotten cannot add virtualhost error (domain already exists)")
	}
}

func TestUpdateListener(t *testing.T) {
	l := newListener()
	var cache WorkQueueCache
	params1 := ListenerParams{
		Name:           "test_1",
		Protocol:       "http",
		TargetHostname: "www.test.inv",
		Conditions: Conditions{
			Hostname: "hostname1.example.com",
			Prefix:   "/test1",
		},
	}
	params2 := ListenerParams{
		Name:           "test_2",
		Protocol:       "http",
		TargetHostname: "www.test.inv",
		Conditions: Conditions{
			Hostname: "hostname2.example.com",
			Prefix:   "/test2",
		},
	}
	paramsTLS1 := TLSParams{}
	listener := l.createListener(params1, paramsTLS1)
	cache.listeners = append(cache.listeners, listener)
	err := l.updateListener(&cache, params2, paramsTLS1)
	if err != nil {
		t.Errorf("Error: %s", err)
	}

	if len(cache.listeners) != 1 {
		t.Errorf("Expected length of 1 (got %d)", len(cache.listeners))
	}
	cachedListener := cache.listeners[0].(*api.Listener)
	if cachedListener.Name != "l_http" {
		t.Errorf("Expected l_http (got %s)", cachedListener.Name)
	}

	manager, err := l.getListenerHTTPConnectionManager(cachedListener)
	routeSpecifier, err := l.getListenerRouteSpecifier(manager)
	if err != nil {
		t.Errorf("Error: %s", err)
	}
	if len(routeSpecifier.RouteConfig.VirtualHosts) != 2 {
		t.Errorf("Expected length of 2 (got %d)", len(routeSpecifier.RouteConfig.VirtualHosts))
	}
	if len(routeSpecifier.RouteConfig.VirtualHosts[0].Domains) != 1 {
		t.Errorf("Expected length of 1 (got %d)", len(routeSpecifier.RouteConfig.VirtualHosts[0].Domains))
	}
	if len(routeSpecifier.RouteConfig.VirtualHosts[1].Domains) != 1 {
		t.Errorf("Expected length of 1 (got %d)", len(routeSpecifier.RouteConfig.VirtualHosts[0].Domains))
	}
	if routeSpecifier.RouteConfig.VirtualHosts[0].Domains[0] != "hostname1.example.com" {
		t.Errorf("Expected hostname1.example.com (got %s)", routeSpecifier.RouteConfig.VirtualHosts[1].Domains[0])
	}
	if routeSpecifier.RouteConfig.VirtualHosts[1].Domains[0] != "hostname2.example.com" {
		t.Errorf("Expected hostname2.example.com (got %s)", routeSpecifier.RouteConfig.VirtualHosts[2].Domains[0])
	}
}
