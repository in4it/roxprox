package envoy

import (
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	api "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	gzip "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/gzip/compressor/v3"
	compressor "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/compressor/v3"
	"github.com/golang/protobuf/ptypes"
	any "github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/wrappers"
)

type Compression struct{}

func newCompression() *Compression {
	return &Compression{}
}

func (c *Compression) updateListenersWithCompression(cache *WorkQueueCache, params CompressionParams) error {
	// update listener
	for listenerKey := range cache.listeners {
		ll := cache.listeners[listenerKey].(*api.Listener)
		for filterchainID := range ll.FilterChains {
			for filterID := range ll.FilterChains[filterchainID].Filters {
				// get manager
				manager, err := getManager((ll.FilterChains[filterchainID].Filters[filterID].ConfigType).(*api.Filter_TypedConfig))
				if err != nil {
					return err
				}

				// get compression config
				compressorConfigEncoded, err := c.getCompressionFilterEncoded(params)
				if err != nil {
					return err
				}

				// update http filter
				updateHTTPFilterWithConfig(&manager.HttpFilters, "envoy.filters.http.compressor", compressorConfigEncoded)

				// update manager in cache
				pbst, err := ptypes.MarshalAny(&manager)
				if err != nil {
					return err
				}
				ll.FilterChains[filterchainID].Filters[filterID].ConfigType = &api.Filter_TypedConfig{
					TypedConfig: pbst,
				}

			}

		}

	}

	return nil
}

func (c *Compression) getCompressionFilterEncoded(params CompressionParams) (*any.Any, error) {
	compressionFilter, err := c.getCompressionFilter(params)
	if compressionFilter == nil {
		return nil, nil
	}
	compressionFilterEncoded, err := ptypes.MarshalAny(compressionFilter)
	if err != nil {
		return nil, err
	}
	return compressionFilterEncoded, nil
}

func (c *Compression) getCompressionFilter(compression CompressionParams) (*compressor.Compressor, error) {
	if compression.Type == "gzip" {
		// set gzip config
		gzip := gzip.Gzip{
			CompressionLevel:    gzip.Gzip_DEFAULT_COMPRESSION,
			CompressionStrategy: gzip.Gzip_DEFAULT_STRATEGY,
		}
		gzipEncoded, err := ptypes.MarshalAny(&gzip)
		if err != nil {
			return nil, err
		}
		// set compressor config
		httpFilterConfig := compressor.Compressor{
			CompressorLibrary: &core.TypedExtensionConfig{
				Name:        "text_optimized",
				TypedConfig: gzipEncoded,
			},
		}
		if compression.ContentLength != 0 {
			httpFilterConfig.ContentLength = &wrappers.UInt32Value{
				Value: compression.ContentLength,
			}
		}
		if len(compression.ContentType) != 0 {
			httpFilterConfig.ContentType = compression.ContentType
		}
		httpFilterConfig.DisableOnEtagHeader = compression.DisableOnEtagHeader

		return &httpFilterConfig, nil
	}
	return nil, nil
}
