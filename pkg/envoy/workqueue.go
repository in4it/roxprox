package envoy

import (
	"fmt"
	"sync/atomic"

	"github.com/envoyproxy/go-control-plane/pkg/cache"
	"github.com/google/uuid"
	storage "github.com/in4it/envoy-autocert/pkg/storage"
)

type WorkQueue struct {
	cs             chan WorkQueueSubmissionState
	c              chan WorkQueueItem
	callback       *Callback
	cache          WorkQueueCache
	cert           *Cert
	listener       *Listener
	cluster        *Cluster
	acmeContact    string
	latestSnapshot cache.Snapshot
}

func NewWorkQueue(s storage.Storage, acmeContact string) (*WorkQueue, error) {
	cs := make(chan WorkQueueSubmissionState)
	c := make(chan WorkQueueItem)
	cert, err := newCert(s, acmeContact)
	if err != nil {
		return nil, err
	}

	w := &WorkQueue{c: c, cs: cs, cert: cert, listener: newListener(), cluster: newCluster()}

	// run queue to resolve dependencies
	go w.resolveDependsOn()

	return w, nil
}
func (w *WorkQueue) InitCache() cache.SnapshotCache {
	w.cache.snapshotCache = cache.NewSnapshotCache(false, Hasher{}, logger)
	return w.cache.snapshotCache
}
func (w *WorkQueue) InitCallback() *Callback {
	w.callback = newCallback()
	go w.runUpdateXDSForNewNodes()
	return w.callback
}
func (w *WorkQueue) WaitForFirstEnvoy() {
	<-w.callback.waitForEnvoy
}

func (w *WorkQueue) Submit(items []WorkQueueItem) (string, error) {
	id := uuid.New().String()
	var updateXds bool

	for k, item := range items {
		itemID := uuid.New().String()
		items[k].id = itemID
		switch item.Action {
		case "createCluster":
			w.cache.clusters = append(w.cache.clusters, w.cluster.createCluster(item.ClusterParams))
			item.state = "finished"
			updateXds = true
		case "createListener":
			if len(w.cache.listeners) == 0 {
				w.cache.listeners = append(w.cache.listeners, w.listener.createListener(item.ListenerParams, TLSParams{}))
				item.state = "finished"
			} else {
				err := w.listener.updateListener(&w.cache, item.ListenerParams, TLSParams{})
				if err != nil {
					logger.Errorf("updateListener error: %s", err)
					item.state = "error"
				} else {
					item.state = "finished"
				}
			}
			updateXds = true
		case "createTLSListener":
			if len(w.cache.listeners) == 1 {
				w.cache.listeners = append(w.cache.listeners, w.listener.createListener(item.ListenerParams, item.TLSParams))
				item.state = "finished"
			} else {
				err := w.listener.updateListener(&w.cache, item.ListenerParams, item.TLSParams)
				if err != nil {
					logger.Errorf("updateListener error: %s", err)
					item.state = "error"
				} else {
					item.state = "finished"
				}
			}
			updateXds = true
		case "updateListenerWithChallenge":
			err := w.listener.updateListenerWithChallenge(&w.cache, item.ChallengeParams)
			if err != nil {
				item.state = "error"
				logger.Errorf("updateListenerWithChallenge error: %s", err)
			} else {
				item.state = "finished"
			}
			// update Xds immediately
			w.updateXds()
		case "updateListenerWithNewCert":
			err := w.listener.updateListenerWithNewCert(&w.cache, item.TLSParams)
			if err != nil {
				item.state = "error"
				logger.Errorf("updateListenerWithNewCert error: %s", err)
			} else {
				item.state = "finished"
			}
			updateXds = true
		case "acceptChallenge":
			err := w.cert.acceptChallenge(item.ChallengeParams)
			if err != nil {
				item.state = "error"
				logger.Errorf("acceptChallenge error: %s", err)
			} else {
				item.state = "finished"
			}
		case "waitForValidation":
			item.state = "pending"
			// wait for validation
			go w.waitForValidation(id, itemID, item.ChallengeParams)
		case "verifyDomains":
			workQueueItems, err := w.cert.verifyDomains(item.CreateCertParams)
			if err != nil {
				logger.Errorf("verifyDomains error: %s", err)
				item.state = "error"
			}
			_, err = w.Submit(workQueueItems)
			if err != nil {
				logger.Errorf("verifyDomains error: %s", err)
				item.state = "error"
			}
			if item.state != "error" {
				item.state = "finished"
			}
		case "createCertAfterVerification":
			// create a list of items to depend on
			var dependsOnItemIDs []string
			for _, item := range items {
				if item.Action == "waitForValidation" {
					if item.id == "" {
						logger.Errorf("Couldn't determine id for waitForValidation of %s", item.ChallengeParams.Domain)
					} else {
						dependsOnItemIDs = append(dependsOnItemIDs, item.id)
					}
				}
			}
			// create a depends on work queue item
			w.c <- WorkQueueItem{
				Action:           "createCert",
				DependsOn:        id,               // depends on verification (this submission)
				DependsOnItemIDs: dependsOnItemIDs, // depends on specific items
				CreateCertParams: item.CreateCertParams,
			}
		case "createCert":
			certBundle, privateKeyPem, err := w.cert.CreateCert(item.CreateCertParams)
			if err != nil {
				logger.Errorf("error while creating cert: %s", err)
				item.state = "error"
			} else {
				w.Submit([]WorkQueueItem{
					{
						Action: "updateListenerWithNewCert",
						TLSParams: TLSParams{
							Name:       item.CreateCertParams.Name,
							CertBundle: certBundle,
							PrivateKey: privateKeyPem,
						},
					},
				})
				item.state = "finished"
			}
		default:
			logger.Errorf("Wrong action submitted to workingqueue")
		}
	}

	if updateXds {
		w.updateXds()
	}

	return id, nil
}
func InArray(a []string, v string) (ret bool, i int) {
	for i = range a {
		if ret = a[i] == v; ret {
			return ret, i
		}
	}
	return false, -1
}
func (w *WorkQueue) updateXds() {
	atomic.AddInt64(&w.cache.version, 1)
	w.latestSnapshot = cache.NewSnapshot(fmt.Sprint(w.cache.version), nil, w.cache.clusters, nil, w.cache.listeners)
	var nodeUpdated []string
	for _, v := range w.callback.connections {
		if ret, _ := InArray(nodeUpdated, v.Id); !ret {
			nodeUpdated = append(nodeUpdated, v.Id)
			w.updateXdsForNode(v.Id)
		}
	}
}
func (w *WorkQueue) updateXdsForNode(node string) {
	if w.cache.version > 0 {
		logger.Debugf("Updating snapshot for: %s to version %d", node, w.cache.version)
		w.cache.snapshotCache.SetSnapshot(node, w.latestSnapshot)
	} else {
		logger.Debugf("Still at version 0, waiting for init")
	}
}
func (w *WorkQueue) runUpdateXDSForNewNodes() {
	for {
		newNode := <-w.callback.newNode
		logger.Debugf("Discovered new node: %s", newNode.id)
		w.updateXdsForNode(newNode.id)
	}
}

func (w *WorkQueue) removeElementFromState(slice []WorkQueueSubmissionState, s int) []WorkQueueSubmissionState {
	return append(slice[:s], slice[s+1:]...)
}

func (w *WorkQueue) resolveDependsOn() {
	var stateQueue []WorkQueueSubmissionState
	for {
		item := <-w.c
		var finished []bool
		logger.Debugf("Starting to resolv dependencies for: %+v", item)
		for _, dependsOnItemID := range item.DependsOnItemIDs {
			stateQueue = append(stateQueue, <-w.cs)
			for k, completedItem := range stateQueue {
				logger.Debugf("looping completeditem: %+v", completedItem)
				if item.DependsOn == completedItem.id && dependsOnItemID == completedItem.itemID {
					logger.Debugf("Completed itemID: %s with status %s", completedItem.id, completedItem.state)
					if completedItem.state == "finished" {
						finished = append(finished, true)
					}
					stateQueue = w.removeElementFromState(stateQueue, k)
				} else {
					logger.Debugf("No match found for item: %+v", completedItem)
				}
			}
		}
		allItemsFinished := true
		for _, v := range finished {
			if !v {
				logger.Debugf("resolveDependsOn: Item has failed, will not run action")
				allItemsFinished = false
			}
		}
		if allItemsFinished && len(finished) > 0 {
			logger.Debugf("Submit item %s again without dependency", item.id)
			item.DependsOn = ""
			item.DependsOnItemIDs = []string{}
			w.Submit([]WorkQueueItem{item})
		}
	}
}

func (w *WorkQueue) waitForValidation(id, itemID string, params ChallengeParams) {

	// async wait for authz
	result, err := w.cert.a.WaitForAuthz(params.Domain, params.AuthzURI)
	if err != nil {
		logger.Debugf("Error while waiting for validation: %s", err)
		// set status to error
		logger.Debugf("Submitting id: %s, state: error, itemID: %s", id, itemID)
		w.cs <- WorkQueueSubmissionState{id: id, state: "error", itemID: itemID}
		return
	}
	if result {
		logger.Debugf("Authorization successful for domain: %s", params.Domain)
		// set status to finished
		logger.Debugf("Submitting id: %s, state: finished, itemID: %s", id, itemID)
		w.cs <- WorkQueueSubmissionState{id: id, state: "finished", itemID: itemID}
	}
}