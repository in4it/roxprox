package envoy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	"github.com/in4it/roxprox/pkg/storage"
	localStorage "github.com/in4it/roxprox/pkg/storage/local"
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
	HTTPRouterFilter := x.workQueue.listener.newHTTPRouterFilter()
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
	httpFilters := x.workQueue.listener.newHTTPRouterFilter()
	manager := x.workQueue.listener.newManager(strings.Replace("testlistener", "l_", "r_", 1), []*route.VirtualHost{}, httpFilters)
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
}
