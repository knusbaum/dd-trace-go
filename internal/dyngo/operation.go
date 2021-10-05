// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

package dyngo

import (
	"reflect"
	"sync"
)

type (
	// Option is the interface of operation options.
	Option interface {
		apply(s *Operation)
	}
	optionFunc func(s *Operation)
)

func (f optionFunc) apply(s *Operation) {
	f(s)
}

// WithParent allows defining the parent operation of the one being created.
func WithParent(parent *Operation) Option {
	return optionFunc(func(op *Operation) {
		op.parent = parent
	})
}

// Operation structure allowing to subscribe to operation events and to navigate in the operation stack. Events
// bubble-up the operation stack, which allows listening to future events that might happen in the operation lifetime.
type Operation struct {
	parent                    *Operation
	expectedResType           reflect.Type
	onStart, onData, onFinish eventRegister

	disabled bool
	mu       sync.RWMutex
}

// StartOperation starts a new operation along with its arguments and emits a start event with the operation arguments.
func StartOperation(args interface{}, opts ...Option) *Operation {
	o := newOperation(opts...)
	o.expectedResType = reflect.TypeOf(args)
	if o.expectedResType == nil {
		return o
	}
	for op := o.Parent(); op != nil; op = op.Parent() {
		op.emitEvent(&op.onStart, o, args)
	}
	return o
}

func newOperation(opts ...Option) *Operation {
	op := &Operation{}
	for _, opt := range opts {
		opt.apply(op)
	}
	return op
}

// Parent return the parent operation. It returns nil for the root operation.
func (o *Operation) Parent() *Operation {
	return o.parent
}

// Finish finishes the operation along with its results and emits a finish event with the operation results.
// The operation is then disabled and its event listeners removed.
func (o *Operation) Finish(results interface{}) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.disabled {
		return
	}
	defer o.disable()
	for op := o; op != nil; op = op.Parent() {
		op.emitEvent(&op.onFinish, o, results)
	}
}

func (o *Operation) disable() {
	o.disabled = true
	o.onStart.clear()
	o.onData.clear()
	o.onFinish.clear()
}

// EmitData allows emitting operation data usually computed in the operation lifetime. Examples include parsed values
// like an HTTP request's JSON body, the HTTP raw body, etc. - data that is obtained by monitoring the operation
// execution, possibly throughout several executions.
func (o *Operation) EmitData(data interface{}) {
	for op := o; op != nil; op = op.Parent() {
		//op.emitDataEvent(o, data)
		op.emitEvent(&op.onData, o, data)
	}
}

// emitEvent calls the event listeners of the given event register when it is not disabled.
func (o *Operation) emitEvent(r *eventRegister, op *Operation, v interface{}) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.disabled {
		return
	}
	r.callListeners(op, v)
}

// OnStart registers the start event listener whose argument type is described by the argsPtr argument which must be a
// nil pointer to the expected argument type. For example:
//
//     // Register a start event listener whose result type is MyOpArguments
//     op.OnStart((*MyOpArguments), func(op *Operation, v interface{}) {
//         args := v.(MyOpArguments)
//     })
//
func (o *Operation) OnStart(argsPtr interface{}, l EventListenerFunc) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.disabled {
		return
	}
	o.onStart.add(reflect.TypeOf(argsPtr), l)
}

// OnData registers the data event listener whose data type is described by the dataPtr argument which must be a
// nil pointer to the expected data type. For example:
//
//     // Register a data event listener whose result type is MyOpData
//     op.OnData((*MyOpData), func(op *Operation, v interface{}) {
//         args := v.(MyOpData)
//     })
//
func (o *Operation) OnData(dataPtr interface{}, l EventListenerFunc) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.disabled {
		return
	}
	o.onData.add(reflect.TypeOf(dataPtr), l)
}

// OnFinish registers the finish event listener whose result type is described by the resPtr argument which must be a
// nil pointer to the expected result type. For example:
//
//     // Register a finish event listener whose result type is MyOpResults
//     op.OnFinish((*MyOpResults), func(op *Operation, v interface{}) {
//         args := v.(MyOpResults)
//     })
//
func (o *Operation) OnFinish(resPtr interface{}, l EventListenerFunc) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.disabled {
		return
	}
	o.onFinish.add(reflect.TypeOf(resPtr), l)
}
