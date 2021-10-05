// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

package dyngo

import (
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
)

type (
	// eventRegister implements a thread-safe list of event listeners.
	eventRegister struct {
		mu        sync.RWMutex
		listeners eventListenerMap
	}

	// eventListenerMap is the map of event listeners. The list of listeners are indexed by the operation argument or
	// result type the event listener expects. The map key type is a struct of the fully-qualified type name (type
	// package path and name) to uniquely identify the argument/result type instead of using the interface type
	// reflect.Type that can possibly lead to panics if the actual value isn't hashable as required by map keys.
	eventListenerMap      map[reflect.Type][]eventListenerMapEntry
	eventListenerMapEntry struct {
		id       eventListenerID
		callback EventListenerFunc
	}

	// eventListenerID is the unique ID of an event when registering it. It allows to find it back and remove it from
	// the list of event listeners when unregistering it.
	eventListenerID uint32

	// eventListenerKey allows to lookup for the event listener in the event register.
	eventListenerKey struct {
		key reflect.Type
		id  eventListenerID
	}
)

// lastID is the last event listener ID that was given to the latest event listener.
var lastID eventListenerID

// nextID atomically increments lastID and returns the new event listener ID to use.
func nextID() eventListenerID {
	return eventListenerID(atomic.AddUint32((*uint32)(&lastID), 1))
}

func (r *eventRegister) add(k reflect.Type, l EventListenerFunc) eventListenerID {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.listeners == nil {
		r.listeners = make(eventListenerMap)
	}
	// id is computed when the lock is exclusively taken so that we know listeners are added in incremental id order.
	// This allows to use the optimized sort.Search() function to remove the entry.
	id := nextID()
	r.listeners[k] = append(r.listeners[k], eventListenerMapEntry{
		id:       id,
		callback: l,
	})
	return id
}

func (r *eventRegister) remove(k reflect.Type, id eventListenerID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	listeners := r.listeners[k]
	len := len(listeners)
	i := sort.Search(len, func(i int) bool {
		return listeners[i].id >= id
	})
	if i < len && listeners[i].id == id {
		r.listeners[k] = append(listeners[:i], listeners[i+1:]...)
	}
}

func (r *eventRegister) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listeners = nil
}

func (r *eventRegister) callListeners(op *Operation, data interface{}) {
	dataT := reflect.TypeOf(data)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.listeners[dataT] {
		e.callback(op, data)
	}
}

// EventListenerFunc is an alias to the event listener function.
// The listener must perform the type-assertion to the expected type.
// Helper function closures should be used to enforce the type-safety,
// such as:
//
//   func (l func(*dyngo.Operation, T)) EventListenerFunc {
//      return func (op *dyngo.Operation, v interface{}) {
//         l(op, v.(T))
//      }
//   }
type EventListenerFunc func(op *Operation, v interface{})
