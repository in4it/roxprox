package envoy

import (
	extAuthz "github.com/envoyproxy/go-control-plane/envoy/config/filter/http/ext_authz/v2"
)

type AuthzFilter struct{}

func newAuthzFilter() *AuthzFilter {
	return &AuthzFilter{}
}

func (a *AuthzFilter) updateListenerWithAuthzFilter(cache *WorkQueueCache, params ListenerParams) error {
	return nil
}

func (a *AuthzFilter) getAuthzFilter() *extAuthz.ExtAuthz {
	return nil
}
