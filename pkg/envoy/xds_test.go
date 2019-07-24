package envoy

import (
	"fmt"
	"strings"
	"testing"

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
	if workQueueItems[0].ListenerParams.Conditions.Hostname != "test1-2.example.com" {
		t.Errorf("Expected test1-2.example.com to be deleted")
		return
	}
	if workQueueItems[1].Action != "deleteCluster" {
		t.Errorf("Expected second action to be deleteCluster")
		return
	}
	_, err = x.workQueue.Submit(workQueueItems)
	if err != nil {
		t.Errorf("WorkQueue error: %s", err)
		return
	}

	workQueueItems = []WorkQueueItem{}
	// try again delete, no deleteRoute actions can be found

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

	deleteRouteFound := false
	additionFound := false
	for _, v := range newItems {
		if v.Action == "deleteRoute" && v.ListenerParams.Conditions.Hostname == "test1-1.example.com" {
			deleteRouteFound = true
		}
		if v.Action == "createListener" && v.ListenerParams.Conditions.Hostname == "test1-3.example.com" {
			additionFound = true
		}
		if v.Action == "deleteRoute" && v.ListenerParams.Conditions.Hostname == "test1-2.example.com" {
			t.Errorf("Found deleteRoute for test1-2.example.com (Found: %+v)", v)
		}
	}
	if !deleteRouteFound {
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

	deleteRoute1Found := false
	deleteRoute2Found := false
	deleteRoute3Found := false
	for _, v := range newItems {
		if v.Action == "deleteRoute" && v.ListenerParams.Conditions.Hostname == "test-multiplerules-2.example.com" {
			deleteRoute1Found = true
		}
		if v.Action == "deleteRoute" && v.ListenerParams.Conditions.Hostname == "test-multiplerules-5.example.com" {
			deleteRoute2Found = true
		}
		if v.Action == "deleteRoute" && v.ListenerParams.Conditions.Hostname == "test-multiplerules-6.example.com" {
			deleteRoute3Found = true
		}
	}
	if !deleteRoute1Found {
		t.Errorf("Delete route for test-multiplerules-2.example.com not found")
		return
	}
	if !deleteRoute2Found {
		t.Errorf("Delete route for test-multiplerules-5.example.com not found")
		return
	}
	if !deleteRoute3Found {
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
