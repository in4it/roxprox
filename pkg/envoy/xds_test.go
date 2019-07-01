package envoy

import (
	"fmt"
	"testing"

	"github.com/in4it/roxprox/pkg/storage"
	localStorage "github.com/in4it/roxprox/pkg/storage/local"
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
	x := NewXDS(s, "")
	var workQueueItems []WorkQueueItem
	ObjectFileNames := []string{"test1.yaml", "test2.yaml", "test3.yaml"}
	for _, filename := range ObjectFileNames {
		newItems, err := x.putObject(filename)
		if err != nil {
			t.Errorf("PutObject failed: %s", err)
			return
		}
		workQueueItems = append(workQueueItems, newItems...)
	}
	fmt.Printf("%+d", len(workQueueItems))
	_, err = x.workQueue.Submit(workQueueItems)
	if err != nil {
		t.Errorf("WorkQueue error: %s", err)
		return
	}
	fmt.Printf("%+v", x.workQueue.cache.listeners)
}
