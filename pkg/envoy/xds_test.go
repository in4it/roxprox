package envoy

import (
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
		if obj, err := x.s.GetCachedObjectName(filename); err != nil {
			t.Errorf("Error while getting cache: %s", err)
		} else {
			if obj.Kind != "rule" && obj.Kind != "jwtProvider" {
				t.Errorf("Object in cache of unknown format: %s", obj.Kind)
			}
		}
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
	if workQueueItems[0].ListenerParams.Conditions.Hostname != "test1-1.example.com" {
		t.Errorf("Expected test1-1.example.com to be deleted")
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
