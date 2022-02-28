package envoy

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	clusterAPI "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	api "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	listenerAPI "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	als "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/ptypes"
	"github.com/in4it/roxprox/pkg/storage"
	localStorage "github.com/in4it/roxprox/pkg/storage/local"
	"github.com/in4it/roxprox/proto/notification"
	"github.com/juju/loggo"
)

func initStorage() (storage.Storage, error) {
	return storage.NewStorage("local", localStorage.Config{Path: "testdata"})
}

func TestPutObject(t *testing.T) {
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	var workQueueItems []WorkQueueItem
	ObjectFileNames := []string{"test1.yaml", "test2.yaml", "test3.yaml", "test-jwtprovider.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		workQueueItems = append(workQueueItems, newItems...)
	}
	if len(workQueueItems) != 10 {
		t.Errorf("expecting 10 work queue items")
		return
	}
	_, err = x.workQueue.Submit(workQueueItems)
	if err != nil {
		t.Errorf("WorkQueue error: %s", err)
		return
	}
	for _, filename := range ObjectFileNames {
		if objs, err := x.s.GetCachedObjectName(filename); err != nil {
			t.Errorf("Error while getting cache: %s", err)
		} else {
			for _, obj := range objs {
				if obj.Kind != "rule" && obj.Kind != "jwtProvider" {
					t.Errorf("Object in cache of unknown format: %s", obj.Kind)
				}
			}
		}
	}
}

func TestPutObjectWithoutCluster(t *testing.T) {
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	var workQueueItems []WorkQueueItem
	ObjectFileNames := []string{"test1.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		workQueueItems = append(workQueueItems, newItems...)
	}

	// delete cluster object
	workQueueItems = workQueueItems[1:]
	fmt.Printf("%+v\n", workQueueItems)

	_, err = x.workQueue.Submit(workQueueItems)
	if err != nil {
		t.Errorf("WorkQueue error: %s", err)
		return
	}

	// no version increment, nothing added, because we removed the cluster
	if x.workQueue.GetVersion() != 0 {
		t.Errorf("Expected version to be 0")
		return
	}

}

func TestDeleteObject(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	var workQueueItems []WorkQueueItem
	ObjectFileNames := []string{"test1.yaml", "test2.yaml", "test3.yaml", "test-jwtprovider.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		workQueueItems = append(workQueueItems, newItems...)
	}
	_, err = x.workQueue.Submit(workQueueItems)
	if err != nil {
		t.Errorf("WorkQueue error: %s", err)
		return
	}

	// delete object
	workQueueItems = []WorkQueueItem{}
	ObjectFileNames = []string{"test1.yaml"}

	for _, filename := range ObjectFileNames {
		newItems, err := x.deleteObject(filename)
		if err != nil {
			t.Errorf("deleteObject failed: %s", err)
			return
		}
		workQueueItems = append(workQueueItems, newItems...)
	}

	if len(workQueueItems) != 2 {
		t.Errorf("expected 2 work queue items")
		return
	}
	if workQueueItems[0].Action != "deleteRule" || workQueueItems[0].ListenerParams.Conditions.Hostname != "test1-2.example.com" {
		t.Errorf("Expected test1-2.example.com to be deleted")
		return
	}
	if workQueueItems[1].Action != "deleteJwtRule" || workQueueItems[1].ListenerParams.Conditions.Hostname != "test1-2.example.com" {
		t.Errorf("Expected test1-2.example.com to be deleted")
		return
	}

	_, err = x.workQueue.Submit(workQueueItems)
	if err != nil {
		t.Errorf("WorkQueue error: %s", err)
		return
	}

	workQueueItems = []WorkQueueItem{}
	// try again delete, no deleteRule actions can be found

	_, err = x.deleteObject("test1.yaml")
	if err == nil {
		t.Errorf("Expected deleteObject to fail with error")
		return
	}

}
func TestChange(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	workQueueItems := []WorkQueueItem{}
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")

	workQueueItems, err = x.putObject("test1.yaml")
	if err != nil {
		t.Errorf("PutObject failed: %s", err)
		return
	}

	_, err = x.workQueue.Submit(workQueueItems)
	if err != nil {
		t.Errorf("WorkQueue error: %s", err)
		return
	}

	x.s.SetStoragePath("testdata/changes")
	newItems, err := x.putObject("test1.yaml")
	if err != nil {
		t.Errorf("putObject error: %s", err)
		return
	}

	deleteRuleFound := false
	additionFound := false
	for _, v := range newItems {
		if v.Action == "deleteRule" && v.ListenerParams.Conditions.Hostname == "test1-1.example.com" {
			deleteRuleFound = true
		}
		if v.Action == "createRule" && v.ListenerParams.Conditions.Hostname == "test1-3.example.com" {
			additionFound = true
		}
		if v.Action == "deleteRule" && v.ListenerParams.Conditions.Hostname == "test1-2.example.com" {
			t.Errorf("Found deleteRule for test1-2.example.com (Found: %+v)", v)
		}
	}
	if !deleteRuleFound {
		t.Errorf("Delete route not found")
		return
	}
	if !additionFound {
		t.Errorf("additional condition not found")
		return
	}

	logger.Debugf("Delete route found, additional condition found")

	_, err = x.workQueue.Submit(newItems)
	if err != nil {
		t.Errorf("WorkQueue error: %s", err)
		return
	}
}
func TestMultipleRulesChange(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	workQueueItems := []WorkQueueItem{}
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")

	workQueueItems, err = x.putObject("test-multiplerules.yaml")
	if err != nil {
		t.Errorf("PutObject failed: %s", err)
		return
	}

	elementsFound := 0
	for _, item := range workQueueItems {
		if strings.HasPrefix(item.ListenerParams.Name, "test-multiplerules-") {
			elementsFound++
		}
	}

	if elementsFound != 6 {
		t.Errorf("Should have found 6 Listener elements (one for every match) in workQueueItems (found %d)", elementsFound)
		return

	}

	_, err = x.workQueue.Submit(workQueueItems)
	if err != nil {
		t.Errorf("WorkQueue error: %s", err)
		return
	}

	x.s.SetStoragePath("testdata/changes")
	newItems, err := x.putObject("test-multiplerules.yaml")
	if err != nil {
		t.Errorf("putObject error: %s", err)
		return
	}

	deleteRule1Found := false
	deleteRule2Found := false
	deleteRule3Found := false
	for _, v := range newItems {
		if v.Action == "deleteRule" && v.ListenerParams.Conditions.Hostname == "test-multiplerules-2.example.com" {
			deleteRule1Found = true
		}
		if v.Action == "deleteRule" && v.ListenerParams.Conditions.Hostname == "test-multiplerules-5.example.com" {
			deleteRule2Found = true
		}
		if v.Action == "deleteRule" && v.ListenerParams.Conditions.Hostname == "test-multiplerules-6.example.com" {
			deleteRule3Found = true
		}
	}
	if !deleteRule1Found {
		t.Errorf("Delete route for test-multiplerules-2.example.com not found")
		return
	}
	if !deleteRule2Found {
		t.Errorf("Delete route for test-multiplerules-5.example.com not found")
		return
	}
	if !deleteRule3Found {
		t.Errorf("Delete route for test-multiplerules-6.example.com not found")
		return
	}

	logger.Debugf("Delete routes found")

	_, err = x.workQueue.Submit(newItems)
	if err != nil {
		t.Errorf("WorkQueue error: %s", err)
		return
	}

}
func TestDeleteDuplicateJwtRule(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-jwtprovider.yaml", "test4.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}

	// update object (with rule deletion)
	x.s.SetStoragePath("testdata/changes")
	newWorkQueueItems, err := x.putObject("test4.yaml")
	if err != nil {
		t.Errorf("putObject error: %s", err)
		return
	}

	for _, item := range newWorkQueueItems {
		if item.Action == "deleteJwtRule" {
			t.Errorf("Found deleteJwtRule in WorkQueueActions. Jwt rule shouldn't be deleted, as there is still a condition for this exact rule")
			return
		}
	}

	_, err = x.workQueue.Submit(newWorkQueueItems)
	if err != nil {
		t.Errorf("WorkQueue error: %s", err)
		return
	}
}

func TestJwtAndRuleInSingleFile(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test5.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
}
func TestJwtRuleOrder(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test4.yaml", "test-jwtprovider.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
}

func TestImportObjects(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")

	err = x.ImportObjects()
	if err != nil {
		t.Errorf("ImportObjects error: %s", err)
		return
	}
}

func TestAuthzObject(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-authz.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	HTTPRouterFilter := x.workQueue.listener.newHTTPRouterFilter("l_http")
	if len(HTTPRouterFilter) < 2 {
		t.Errorf("Less than 2 http router filters")
		return
	}
	if HTTPRouterFilter[0].GetName() != "envoy.ext_authz" {
		t.Errorf("ext_authz not found in httprouter filter")
		return
	}
}

func TestTracingObject(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-tracing.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	httpFilters := x.workQueue.listener.newHTTPRouterFilter("l_http")
	manager := x.workQueue.listener.newManager("l_http", strings.Replace("testlistener", "l_", "r_", 1), []*route.VirtualHost{}, httpFilters, false)
	if manager.Tracing == nil {
		t.Errorf("No tracing config found")
		return
	}
	if manager.Tracing.GetClientSampling().Value != 100 {
		t.Errorf("Tracing: wrong sampling information found")
		return
	}
	if manager.Tracing.GetRandomSampling().Value != 99 {
		t.Errorf("Tracing: wrong sampling information found")
		return
	}
	if manager.Tracing.GetOverallSampling().Value != 98 {
		t.Errorf("Tracing: wrong sampling information found")
		return
	}

}

func TestDirectResponseObject(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-directresponse.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	out, err := x.workQueue.listener.printListener(&x.workQueue.cache)
	if err != nil {
		t.Errorf("listener print error: %s", err)
		return
	}
	fmt.Printf("%s\n", out)
}
func TestClusterWithHealthcheck(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-healthcheck.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	out, err := x.workQueue.cluster.PrintCluster(&x.workQueue.cache, "test-healthcheck")
	if err != nil {
		t.Errorf("listener print error: %s", err)
		return
	}
	fmt.Printf("%s\n", out)
}

func TestClusterWithWebsockets(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-websockets.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}

	var upgradeConfigs []*route.RouteAction_UpgradeConfig

	for _, listener := range x.workQueue.cache.listeners {
		ll := listener.(*listenerAPI.Listener)
		manager, err := getListenerHTTPConnectionManager(ll)
		if err != nil {
			t.Errorf("Error while getting listener: %s", err)
			return
		}
		routeSpecifier, err := getListenerRouteSpecifier(manager)
		if err != nil {
			t.Errorf("Error while getting routes: %s", err)
			return
		}
		for _, virtualHost := range routeSpecifier.RouteConfig.VirtualHosts {
			for _, virtualHostRoute := range virtualHost.Routes {
				if virtualHostRoute.Action != nil {
					switch reflect.TypeOf(virtualHostRoute.Action).String() {
					case "*envoy_config_route_v3.Route_Route":
						upgradeConfigs = virtualHostRoute.Action.(*route.Route_Route).Route.GetUpgradeConfigs()
					}
				}
			}
		}
		if len(upgradeConfigs) == 0 {
			t.Errorf("Upgrade config is empty")
			return
		}
		if !upgradeConfigs[0].Enabled.Value {
			t.Errorf("Upgrade config is not set to enabled")
			return
		}
		if upgradeConfigs[0].UpgradeType != "websocket" {
			t.Errorf("Upgrade config type is not set to websocket")
			return
		}
	}
}
func TestClusterWithPathRewrite(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-prefixrewrite.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}

	var prefixRewrite string

	for _, listener := range x.workQueue.cache.listeners {
		ll := listener.(*listenerAPI.Listener)
		manager, err := getListenerHTTPConnectionManager(ll)
		if err != nil {
			t.Errorf("Error while getting listener: %s", err)
			return
		}
		routeSpecifier, err := getListenerRouteSpecifier(manager)
		if err != nil {
			t.Errorf("Error while getting routes: %s", err)
			return
		}
		for _, virtualHost := range routeSpecifier.RouteConfig.VirtualHosts {
			for _, virtualHostRoute := range virtualHost.Routes {
				if virtualHostRoute.Action != nil {
					switch reflect.TypeOf(virtualHostRoute.Action).String() {
					case "*envoy_config_route_v3.Route_Route":
						prefixRewrite = virtualHostRoute.Action.(*route.Route_Route).Route.GetPrefixRewrite()
					}
				}
			}
		}
		if prefixRewrite != "/addthis" {
			t.Errorf("Prefix rewrite not found")
			return
		}
	}
}

func TestClusterWithPathRewriteWithChange(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-prefixrewrite.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	ObjectFileNames = []string{"test-prefixrewrite-2.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}

	var prefixRewrite string

	for _, listener := range x.workQueue.cache.listeners {
		ll := listener.(*listenerAPI.Listener)
		manager, err := getListenerHTTPConnectionManager(ll)
		if err != nil {
			t.Errorf("Error while getting listener: %s", err)
			return
		}
		routeSpecifier, err := getListenerRouteSpecifier(manager)
		if err != nil {
			t.Errorf("Error while getting routes: %s", err)
			return
		}
		routeCount := 0
		for _, virtualHost := range routeSpecifier.RouteConfig.VirtualHosts {
			for _, virtualHostRoute := range virtualHost.Routes {
				routeCount++
				if virtualHostRoute.Action != nil {
					switch reflect.TypeOf(virtualHostRoute.Action).String() {
					case "*envoy_config_route_v3.Route_Route":
						prefixRewrite = virtualHostRoute.Action.(*route.Route_Route).Route.GetPrefixRewrite()
					}
				}
			}
		}
		if routeCount != 1 {
			t.Errorf("Expected to only have 1 route. Actual: %d\n", routeCount)
			return
		}
		if prefixRewrite != "/addthis-2" {
			t.Errorf("Prefix rewrite not found: %s\n", prefixRewrite)
			return
		}
	}
}

func TestClusterWithRegexRewrite(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-regexrewrite.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}

	var regexRewrite *matcher.RegexMatchAndSubstitute

	for _, listener := range x.workQueue.cache.listeners {
		ll := listener.(*listenerAPI.Listener)
		manager, err := getListenerHTTPConnectionManager(ll)
		if err != nil {
			t.Errorf("Error while getting listener: %s", err)
			return
		}
		routeSpecifier, err := getListenerRouteSpecifier(manager)
		if err != nil {
			t.Errorf("Error while getting routes: %s", err)
			return
		}
		for _, virtualHost := range routeSpecifier.RouteConfig.VirtualHosts {
			for _, virtualHostRoute := range virtualHost.Routes {
				if virtualHostRoute.Action != nil {
					switch reflect.TypeOf(virtualHostRoute.Action).String() {
					case "*envoy_config_route_v3.Route_Route":
						regexRewrite = virtualHostRoute.Action.(*route.Route_Route).Route.GetRegexRewrite()
					}
				}
			}
		}
		if regexRewrite.Pattern.Regex != "^/service/([^/]+)(/.*)$" {
			t.Errorf("Regex pattern in regex rewrite not found")
			return
		}
		if regexRewrite.GetSubstitution() != "\\2/instance/\\1" {
			t.Errorf("Regex substitution in regex rewrite not found")
			return
		}
	}
}
func TestCompressionObject(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-compression.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	httpFilters := x.workQueue.listener.newHTTPRouterFilter("l_http")
	if len(httpFilters) == 0 {
		t.Errorf("Filters in empty")
		return
	}
	if httpFilters[0].Name != "envoy.filters.http.compressor" {
		t.Errorf("Compressor filter not found")
		return
	}
}
func TestAccessLogServer(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test1.yaml", "test-accesslogserver.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}

	if len(x.workQueue.cache.listeners) == 0 {
		t.Errorf("No Listeners")
		return
	}

	for _, listener := range x.workQueue.cache.listeners {
		ll := listener.(*listenerAPI.Listener)
		manager, err := getListenerHTTPConnectionManager(ll)
		if err != nil {
			t.Errorf("Error while getting listener: %s", err)
			return
		}
		if len(manager.AccessLog) == 0 {
			t.Errorf("No Access Log Configuration found")
			return
		}
		if manager.AccessLog[0].Name != wellknown.HTTPGRPCAccessLog {
			t.Errorf("Access log has wrong name")
			return
		}
		var alsConfig als.HttpGrpcAccessLogConfig
		err = ptypes.UnmarshalAny(manager.AccessLog[0].GetTypedConfig(), &alsConfig)
		if err != nil {
			t.Errorf("Cannot unmarshal HttpGrpcAccessLogConfig typed config")
			return
		}
		if alsConfig.CommonConfig.LogName != "accessLogServerExample" {
			t.Errorf("LogName is not correct within alsConfig: %s", alsConfig.CommonConfig.LogName)
			return
		}

	}
}
func TestRateLimitObject(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-ratelimit.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	httpFilters := x.workQueue.listener.newHTTPRouterFilter("l_http")
	if len(httpFilters) == 0 {
		t.Errorf("Filters in empty")
		return
	}
	if httpFilters[0].Name != "envoy.filters.http.ratelimit" {
		t.Errorf("ratelimit filter not found")
		return
	}
}

func TestReceiveNotification(t *testing.T) {
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")

	req := []*notification.NotificationRequest_NotificationItem{
		{
			Filename:  "test1.yaml",
			EventName: "ObjectCreated:Put",
		},
	}
	err = x.ReceiveNotification(req)
	if err != nil {
		t.Errorf("Error when executing ReceiveNotification: %s", err)
		return
	}
}
func TestMTLSObject(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-mtls.yaml", "test-mtls-rule.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	if len(x.workQueue.cache.listeners) == 0 {
		t.Errorf("No listeners found")
		return
	}
	listener := x.workQueue.cache.listeners[0].(*api.Listener)
	if listener.Name != "l_mtls_test-mtls" {
		t.Errorf("Listener has wrong name: %s (expected l_mtls_test-mtls)", listener.Name)
		return
	}
	if listener.GetAddress().GetSocketAddress().GetPortValue() != 10002 {
		t.Errorf("Listener has wrong port: %d (expected 10002)", listener.GetAddress().GetSocketAddress().GetPortValue())
		return
	}
	for listenerKey := range x.workQueue.cache.listeners {
		ll := x.workQueue.cache.listeners[listenerKey].(*api.Listener)
		if ll.GetName() == "l_mtls_test-mtls" {
			manager, err := getListenerHTTPConnectionManager(ll)
			if err != nil {
				t.Errorf("Couldn't get getListenerHTTPConnectionManager: %s", err)
				return
			}
			if getListenerHTTPFilterIndex("envoy.filters.http.router", manager.HttpFilters) == -1 {
				t.Errorf("envoy.filters.http.router not found in httprouter filter - should be not found")
				return
			}
			routeSpecifier, err := getListenerRouteSpecifier(manager)
			if err != nil {
				t.Errorf("Error while getting routes: %s", err)
				return
			}
			for _, virtualHost := range routeSpecifier.RouteConfig.VirtualHosts {
				for _, virtualHostRoute := range virtualHost.Routes {
					if virtualHostRoute.Action != nil {
						switch reflect.TypeOf(virtualHostRoute.Action).String() {
						case "*envoy_config_route_v3.Route_Route":
							if virtualHostRoute.Action.(*route.Route_Route).Route.GetCluster() != "mtls-testrule" {
								t.Errorf("Route for mtls not found: %s", err)
								return

							}
						}
					}
				}
			}
		}
	}
}

func TestAuthzObjectWithMTLS(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-mtls.yaml", "test-authz.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	for listenerKey := range x.workQueue.cache.listeners {
		ll := x.workQueue.cache.listeners[listenerKey].(*api.Listener)
		if ll.GetName() != "l_http" {
			manager, err := getListenerHTTPConnectionManager(ll)
			if err != nil {
				t.Errorf("getListenerHTTPConnectionManager error: %s", err)
				return
			}
			if getListenerHTTPFilterIndex("envoy.ext_authz", manager.HttpFilters) != -1 {
				t.Errorf("ext_authz found in httprouter filter - should be not found")
				return
			}
		}
	}
}
func TestJWTProviderObjectWithMTLS(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-mtls.yaml", "test-jwtprovider.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	for listenerKey := range x.workQueue.cache.listeners {
		ll := x.workQueue.cache.listeners[listenerKey].(*api.Listener)
		if ll.GetName() != "l_http" {
			manager, err := getListenerHTTPConnectionManager(ll)
			if err != nil {
				t.Errorf("getListenerHTTPConnectionManager error: %s", err)
				return
			}
			if getListenerHTTPFilterIndex("envoy.filters.http.jwt_authn", manager.HttpFilters) != -1 {
				t.Errorf("envoy.filters.http.jwt_authn found in httprouter filter - should be not found")
				return
			}
		}
	}
}

func TestRateLimitObjectWithMTLS(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-mtls.yaml", "test-ratelimit.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	for listenerKey := range x.workQueue.cache.listeners {
		ll := x.workQueue.cache.listeners[listenerKey].(*api.Listener)
		if ll.GetName() != "l_http" {
			manager, err := getListenerHTTPConnectionManager(ll)
			if err != nil {
				t.Errorf("getListenerHTTPConnectionManager error: %s", err)
				return
			}
			if getListenerHTTPFilterIndex("envoy.filters.http.ratelimit", manager.HttpFilters) != -1 {
				t.Errorf("envoy.filters.http.ratelimit found in httprouter filter - should be not found")
				return
			}
		}
	}
}

func TestRateLimitObjectWithMTLS2(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-ratelimit.yaml", "test-mtls.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	for listenerKey := range x.workQueue.cache.listeners {
		ll := x.workQueue.cache.listeners[listenerKey].(*api.Listener)
		if ll.GetName() != "l_http" {
			manager, err := getListenerHTTPConnectionManager(ll)
			if err != nil {
				t.Errorf("getListenerHTTPConnectionManager error: %s", err)
				return
			}
			if getListenerHTTPFilterIndex("envoy.filters.http.ratelimit", manager.HttpFilters) != -1 {
				t.Errorf("envoy.filters.http.ratelimit found in httprouter filter - should be not found")
				return
			}
		}
	}
}
func TestRateLimitObjectWithMTLS3(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-ratelimit-mtls.yaml", "test-mtls.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	for listenerKey := range x.workQueue.cache.listeners {
		ll := x.workQueue.cache.listeners[listenerKey].(*api.Listener)
		if ll.GetName() != "l_http" {
			manager, err := getListenerHTTPConnectionManager(ll)
			if err != nil {
				t.Errorf("getListenerHTTPConnectionManager error: %s", err)
				return
			}
			if getListenerHTTPFilterIndex("envoy.filters.http.ratelimit", manager.HttpFilters) == -1 {
				t.Errorf("envoy.filters.http.ratelimit not found in httprouter filter - should be found")
				return
			}
		}
	}
}
func TestAuthzObjectWithMTLS2(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-authz.yaml", "test-mtls.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	for listenerKey := range x.workQueue.cache.listeners {
		ll := x.workQueue.cache.listeners[listenerKey].(*api.Listener)
		if ll.GetName() != "l_http" {
			manager, err := getListenerHTTPConnectionManager(ll)
			if err != nil {
				t.Errorf("getListenerHTTPConnectionManager error: %s", err)
				return
			}
			if getListenerHTTPFilterIndex("envoy.ext_authz", manager.HttpFilters) != -1 {
				t.Errorf("envoy.ext_authz found in httprouter filter - should be not found")
				return
			}
		}
	}
}
func TestTracingObjectWithMTLS(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-compression.yaml", "test-mtls.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	for listenerKey := range x.workQueue.cache.listeners {
		ll := x.workQueue.cache.listeners[listenerKey].(*api.Listener)
		if ll.GetName() != "l_http" {
			manager, err := getListenerHTTPConnectionManager(ll)
			if err != nil {
				t.Errorf("getListenerHTTPConnectionManager error: %s", err)
				return
			}
			if getListenerHTTPFilterIndex("envoy.filters.http.compressor", manager.HttpFilters) != -1 {
				t.Errorf("envoy.filters.http.compressor found in httprouter filter - should be not found")
				return
			}
		}
	}
}

func TestLuaFilterWithMTLS(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-luafilter.yaml", "test-mtls.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	found := false
	for listenerKey := range x.workQueue.cache.listeners {
		ll := x.workQueue.cache.listeners[listenerKey].(*api.Listener)
		if ll.GetName() != "l_http" {
			found = true
			manager, err := getListenerHTTPConnectionManager(ll)
			if err != nil {
				t.Errorf("getListenerHTTPConnectionManager error: %s", err)
				return
			}
			if getListenerHTTPFilterIndex("envoy.filters.http.lua", manager.HttpFilters) == -1 {
				t.Errorf("envoy.filters.http.lua not found in httprouter filter - should be found")
				return
			}
		}

	}
	if found == false {
		t.Errorf("listener not found")
	}
}
func TestLuaFilterWithMTLS2(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-mtls.yaml", "test-luafilter.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	found := false
	for listenerKey := range x.workQueue.cache.listeners {
		ll := x.workQueue.cache.listeners[listenerKey].(*api.Listener)
		if ll.GetName() != "l_http" {
			found = true
			manager, err := getListenerHTTPConnectionManager(ll)
			if err != nil {
				t.Errorf("getListenerHTTPConnectionManager error: %s", err)
				return
			}
			if getListenerHTTPFilterIndex("envoy.filters.http.lua", manager.HttpFilters) == -1 {
				t.Errorf("envoy.filters.http.lua not found in httprouter filter - should be found")
				return
			}
		}
	}
	if found == false {
		t.Errorf("listener not found")
	}
}

func TestLuaFilterWithMultipleListeners(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-mtls.yaml", "test-cluster-1.yaml", "test-luafilter.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	found := 0
	for listenerKey := range x.workQueue.cache.listeners {
		ll := x.workQueue.cache.listeners[listenerKey].(*api.Listener)
		found++
		manager, err := getListenerHTTPConnectionManager(ll)
		if err != nil {
			t.Errorf("getListenerHTTPConnectionManager error: %s", err)
			return
		}
		if getListenerHTTPFilterIndex("envoy.filters.http.lua", manager.HttpFilters) == -1 {
			t.Errorf("envoy.filters.http.lua not found in httprouter filter - should be found")
			return
		}
	}
	if found != 2 {
		t.Errorf("Not all listeners found")
	}
}

func TestRuleWithNoConditions(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-cluster-empty.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	allClusters := x.workQueue.cache.clusters
	if len(allClusters) != 1 {
		t.Errorf("Expected to have a 1 cluster (got %d)", len(allClusters))
	}

}
func TestRuleWithConnectionTimeout(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-cluster-connection-timeout.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	allClusters := x.workQueue.cache.clusters
	for _, v := range allClusters {
		cluster := v.(*clusterAPI.Cluster)
		if cluster.ConnectTimeout.Seconds != 5 {
			t.Errorf("Cluster Connect timeout is not 5 (got %d)", cluster.ConnectTimeout.Seconds)
		}
	}
}

func TestRuleWithDefaults(t *testing.T) {
	logger.SetLogLevel(loggo.DEBUG)
	s, err := initStorage()
	if err != nil {
		t.Errorf("Couldn't initialize storage: %s", err)
		return
	}
	x := NewXDS(s, "", "")
	ObjectFileNames := []string{"test-cluster-connection-timeout.yaml", "test-cluster-1.yaml", "test-defaults.yaml", "test-prefixrewrite.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		_, err = x.workQueue.Submit(newItems)
		if err != nil {
			t.Errorf("WorkQueue error: %s", err)
			return
		}
	}
	allClusters := x.workQueue.cache.clusters
	checks := []bool{}
	for _, v := range allClusters {
		cluster := v.(*clusterAPI.Cluster)
		if cluster.Name == "test-cluster-connectiontimeout" || cluster.Name == "test-cluster" {
			checks = append(checks, true)
		}
		if cluster.Name == "test-cluster-connectiontimeout" && cluster.ConnectTimeout.Seconds != 5 {
			t.Errorf("Cluster Connect timeout is not 5 (got %d)", cluster.ConnectTimeout.Seconds)
		}
		if cluster.Name == "test-cluster" && cluster.ConnectTimeout.Seconds != 15 {
			t.Errorf("Cluster Connect timeout is not 15 (got %d)", cluster.ConnectTimeout.Seconds)
		}
		if cluster.Name == "test-prefixrewrite" && cluster.ConnectTimeout.Seconds != 15 {
			t.Errorf("Cluster Connect timeout is not 15 (got %d)", cluster.ConnectTimeout.Seconds)
		}
	}
	if len(checks) != 2 {
		t.Errorf("Clusters not found")
	}
}
