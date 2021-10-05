// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

package api

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type (
	// SecurityEvent is a generic security event payload holding an actual security event (eg. a WAF security event),
	// along with its optional context.
	SecurityEvent struct {
		Event   SecEventEvent
		Context []AttackContextOption
	}

	SecEventEvent interface {
		AttackEvents() []*AttackEvent
	}
)

func NewSecurityEvent(event SecEventEvent, opts ...AttackContextOption) *SecurityEvent {
	return &SecurityEvent{Event: event, Context: opts}
}

func (e *SecurityEvent) AddOption(o AttackContextOption) {
	e.Context = append(e.Context, o)
}

// Intake API payloads.
type (
	// AttackEvent intake API payload.
	AttackEvent struct {
		EventID      string           `json:"event_id"`
		EventType    string           `json:"event_type"`
		EventVersion string           `json:"event_version"`
		DetectedAt   time.Time        `json:"detected_at"`
		Type         string           `json:"type"`
		Blocked      bool             `json:"blocked"`
		Rule         *AttackRule      `json:"rule"`
		RuleMatch    *AttackRuleMatch `json:"rule_match"`
		Context      *AttackContext   `json:"context"`
	}

	// AttackRule intake API payload.
	AttackRule struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	// AttackRuleMatch intake API payload.
	AttackRuleMatch struct {
		Operator      string                     `json:"operator"`
		OperatorValue string                     `json:"operator_value"`
		Parameters    []AttackRuleMatchParameter `json:"parameters"`
		Highlight     []string                   `json:"highlight"`
	}

	// AttackRuleMatchParameter intake API payload.
	AttackRuleMatchParameter struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}

	// AttackContext intake API payload.
	AttackContext struct {
		//Actor   *AttackContextActor  `json:"actor,omitempty"`
		Host    AttackContextHost    `json:"host"`
		HTTP    AttackContextHTTP    `json:"http"`
		Service AttackContextService `json:"service"`
		Tags    AttackContextTags    `json:"tags"`
		Span    AttackContextSpan    `json:"span"`
		Trace   AttackContextTrace   `json:"trace"`
		Tracer  AttackContextTracer  `json:"tracer"`
	}

	AttackContextOption func(ctx *AttackContext)

	// TODO(kyle): Is this needed? It's not used anywhere.
	// 	// AttackContextActor intake API payload.
	// 	AttackContextActor struct {
	// 		ContextVersion string               `json:"context_version"`
	// 		IP             AttackContextActorIP `json:"ip"`
	// 	}
	//
	// 	// AttackContextActorIP intake API payload.
	// 	AttackContextActorIP struct {
	// 		Address string `json:"address"`
	// 	}

	// AttackContextHost intake API payload.
	AttackContextHost struct {
		ContextVersion string `json:"context_version"`
		OsType         string `json:"os_type"`
		Hostname       string `json:"hostname"`
	}

	// AttackContextHTTP intake API payload.
	AttackContextHTTP struct {
		ContextVersion string   `json:"context_version"`
		Request        request  `json:"request"`
		Response       response `json:"response"`
	}

	// AttackContextHTTPRequest intake API payload.
	request struct {
		Scheme     string `json:"scheme"`
		Method     string `json:"method"`
		URL        string `json:"url"`
		Host       string `json:"host"`
		Port       int    `json:"port"`
		Path       string `json:"path"`
		Resource   string `json:"resource"`
		RemoteIP   string `json:"remote_ip"`
		RemotePort int    `json:"remote_port"`
	}

	// AttackContextHTTPResponse intake API payload.
	response struct {
		Status int `json:"status"`
	}

	// AttackContextService intake API payload.
	AttackContextService struct {
		ContextVersion string `json:"context_version"`
		Name           string `json:"name"`
		Environment    string `json:"environment"`
		Version        string `json:"version"`
	}

	// AttackContextTags intake API payload.
	AttackContextTags struct {
		ContextVersion string   `json:"context_version"`
		Values         []string `json:"values"`
	}

	// AttackContextTrace intake API payload.
	AttackContextTrace struct {
		ContextVersion string `json:"context_version"`
		ID             string `json:"id"`
	}

	// AttackContextSpan intake API payload.
	AttackContextSpan struct {
		ContextVersion string `json:"context_version"`
		ID             string `json:"id"`
	}

	// AttackContextTracer intake API payload.
	AttackContextTracer struct {
		ContextVersion string `json:"context_version"`
		RuntimeType    string `json:"runtime_type"`
		RuntimeVersion string `json:"runtime_version"`
		LibVersion     string `json:"lib_version"`
	}
)

// NewAttackEvent returns a new attack event payload.
func NewAttackEvent(attackType string, blocked bool, at time.Time, rule *AttackRule, match *AttackRuleMatch, attackCtx *AttackContext) *AttackEvent {
	id, _ := uuid.NewUUID()
	return &AttackEvent{
		EventID:      id.String(),
		EventType:    "appsec.threat.attack",
		EventVersion: "0.1.0",
		DetectedAt:   at,
		Type:         attackType,
		Blocked:      blocked,
		Rule:         rule,
		RuleMatch:    match,
		Context:      attackCtx,
	}
}

func (*AttackEvent) isEvent() {}

type (
	// EventBatch intake API payload.
	EventBatch struct {
		IdempotencyKey string         `json:"idempotency_key"`
		Events         []*AttackEvent `json:"events"`
	}
)

// FromSecurityEvents returns the event batch of the given security events. The given global event context is added
// to each newly created AttackEvent as AttackContext.
func FromSecurityEvents(events []*SecurityEvent, globalContext AttackContextOption) EventBatch {
	id, _ := uuid.NewUUID()
	var batch = EventBatch{
		IdempotencyKey: id.String(),
		Events:         make([]*AttackEvent, 0, len(events)),
	}
	for _, event := range events {
		if event.Event == nil {
			continue
		}
		eventContext := NewAttackContext(event.Context, globalContext)
		events := event.Event.AttackEvents()
		for _, event := range events {
			event.Context = eventContext
			batch.Events = append(batch.Events, event)
		}
	}
	return batch
}

// NewAttackContext creates and returns a new attack context from the given security event contexts. The event local
// and global contexts are separated to avoid allocating a temporary slice merging both - the caller can keep them
// separate without appending them for the time of the call.
func NewAttackContext(opts []AttackContextOption, defaults AttackContextOption) *AttackContext {
	aCtx := &AttackContext{}
	for _, o := range opts {
		o(aCtx)
	}
	if defaults != nil {
		defaults(aCtx)
	}
	return aCtx
}

// GlobalAttackContext is used in conjunction with the WithDefaults option to
// define the default AttackContext
type GlobalAttackContext struct {
	Service AttackContextService
	Tags    AttackContextTags
	Tracer  AttackContextTracer
	Host    AttackContextHost
}

// WithGlobalAttackContext sets the global AttackContext parameters.
func WithGlobalAttackContext(d GlobalAttackContext) AttackContextOption {
	return func(a *AttackContext) {
		a.Service = d.Service
		a.Service.ContextVersion = "0.1.0"
		a.Tags = d.Tags
		a.Tags.ContextVersion = "0.1.0"
		a.Tracer = d.Tracer
		a.Tracer.ContextVersion = "0.1.0"
		a.Host = d.Host
		a.Host.ContextVersion = "0.1.0"
	}
}

func WithHTTP(req *http.Request, status int) AttackContextOption {
	return func(a *AttackContext) {
		host, portStr := splitHostPort(req.Host)
		remoteIP, remotePortStr := splitHostPort(req.RemoteAddr)
		port, _ := strconv.Atoi(portStr)
		remotePort, _ := strconv.Atoi(remotePortStr)
		var scheme string
		isTLS := req.TLS != nil
		if isTLS {
			scheme = "https"
		} else {
			scheme = "http"
		}
		url := fmt.Sprintf("%s://%s%s", scheme, req.Host, req.RequestURI)
		a.HTTP = AttackContextHTTP{
			ContextVersion: "0.1.0",
			Request: request{
				Scheme:     scheme,
				Method:     req.Method,
				URL:        url,
				Host:       host,
				Port:       port,
				Path:       req.RequestURI,
				RemoteIP:   remoteIP,
				RemotePort: remotePort,
			},
			Response: response{
				Status: status,
			},
		}
	}
}

func WithTrace(traceID, spanID uint64) AttackContextOption {
	return func(a *AttackContext) {
		a.Trace = AttackContextTrace{
			ContextVersion: "0.1.0",
			ID:             strconv.FormatUint(traceID, 10),
		}
		a.Span = AttackContextSpan{
			ContextVersion: "0.1.0",
			ID:             strconv.FormatUint(spanID, 10),
		}
	}
}

// splitHostPort splits a network address of the form `host:port` or
// `[host]:port` into `host` and `port`. As opposed to `net.SplitHostPort()`,
// it doesn't fail when there is no port number and returns the given address
// as the host value.
func splitHostPort(addr string) (host string, port string) {
	addr = strings.TrimSpace(addr)
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		return
	}
	if l := len(addr); l >= 2 && addr[0] == '[' && addr[l-1] == ']' {
		// ipv6 without port number
		return addr[1 : l-1], ""
	}
	return addr, ""
}
