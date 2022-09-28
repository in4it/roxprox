package envoy

import (
	api "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	lua "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	"google.golang.org/protobuf/types/known/anypb"
	any "google.golang.org/protobuf/types/known/anypb"
)

type LuaFilter struct{}

func newLuaFilter() *LuaFilter {
	return &LuaFilter{}
}

func (l *LuaFilter) updateListenersWithLuaFilter(cache *WorkQueueCache, params LuaFilterParams) error {
	// update listener
	for listenerKey := range cache.listeners {
		ll := cache.listeners[listenerKey].(*api.Listener)
		if isDefaultListener(ll.GetName()) || "l_mtls_"+params.Listener.MTLS == ll.GetName() { // only update listener if it is default listener / mTLS listener is selected
			for filterchainID := range ll.FilterChains {
				for filterID := range ll.FilterChains[filterchainID].Filters {
					// get manager
					manager, err := getManager((ll.FilterChains[filterchainID].Filters[filterID].ConfigType).(*api.Filter_TypedConfig))
					if err != nil {
						return err
					}
					luaFilterEncoded, err := l.getLuaFilterConfigEncoded(params)
					if err != nil {
						return err
					}

					updateHTTPFilterWithConfig(&manager.HttpFilters, "envoy.filters.http.lua", luaFilterEncoded)

					// update manager in cache
					pbst, err := anypb.New(manager)
					if err != nil {
						return err
					}
					ll.FilterChains[filterchainID].Filters[filterID].ConfigType = &api.Filter_TypedConfig{
						TypedConfig: pbst,
					}
				}
			}
		}
	}

	return nil
}

func (l *LuaFilter) getLuaFilterConfigEncoded(params LuaFilterParams) (*any.Any, error) {
	luaFilter, err := l.getLuaFilterConfig(params)
	if luaFilter == nil {
		return nil, nil
	}
	luaFilterEncoded, err := anypb.New(luaFilter)
	if err != nil {
		return nil, err
	}
	return luaFilterEncoded, nil
}

func (l *LuaFilter) getLuaFilterConfig(params LuaFilterParams) (*lua.Lua, error) {
	if params.Name != "" {
		return &lua.Lua{
			InlineCode: params.InlineCode,
		}, nil
	}
	return nil, nil
}
