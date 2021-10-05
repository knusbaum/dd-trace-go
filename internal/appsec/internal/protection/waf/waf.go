// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

package waf

import (
	"encoding/json"

	"sync"
	"time"

	"gopkg.in/DataDog/dd-trace-go.v1/internal/appsec/intake/api"
	"gopkg.in/DataDog/dd-trace-go.v1/internal/log"

	"github.com/sqreen/go-libsqreen/waf"
	"github.com/sqreen/go-libsqreen/waf/types"
)

type (
	// RawAttackMetadata is the raw attack metadata returned by the WAF when matching.
	RawAttackMetadata struct {
		Time time.Time
		// Block states if the operation where this event happened should be blocked.
		Block bool
		// Metadata is the raw JSON representation of the AttackMetadata slice.
		Metadata []byte
	}

	// AttackMetadata is the parsed metadata returned by the WAF.
	AttackMetadata []struct {
		RetCode int    `json:"ret_code"`
		Flow    string `json:"flow"`
		Step    string `json:"step"`
		Rule    string `json:"rule"`
		Filter  []struct {
			Operator        string        `json:"operator"`
			OperatorValue   string        `json:"operator_value"`
			BindingAccessor string        `json:"binding_accessor"`
			ManifestKey     string        `json:"manifest_key"`
			KeyPath         []interface{} `json:"key_path"`
			ResolvedValue   string        `json:"resolved_value"`
			MatchStatus     string        `json:"match_status"`
		} `json:"filter"`
	}

	WAF struct {
		attacks []RawAttackMetadata
		rule    types.Rule
		sync.Mutex
	}
)

func NewWAF() (*WAF, error) {
	wafRule, err := waf.NewRule(staticWAFRule)
	if err != nil {
		//log.Error("appsec: waf error: %v", err)
		return nil, err
	}
	return &WAF{rule: waf.NewAdditiveContext(wafRule)}, nil
}

func (w *WAF) Close() error {
	return w.rule.Close()
}

func (w *WAF) Attacks() []RawAttackMetadata {
	w.Lock()
	defer w.Unlock()
	if len(w.attacks) == 0 {
		return nil
	}
	a := make([]RawAttackMetadata, len(w.attacks))
	copy(a, w.attacks)
	return a
}

func (w *WAF) Run(values types.DataSet) {
	w.Lock()
	defer w.Unlock()
	action, md, err := w.rule.Run(values, 1*time.Millisecond)
	if err != nil {
		log.Error("appsec: waf error: %v", err)
		return
	}
	if action == types.NoAction {
		return
	}
	w.attacks = append(w.attacks, RawAttackMetadata{Time: time.Now(), Block: action == types.BlockAction, Metadata: md})
}

type WafSecurityEvent []RawAttackMetadata

func (wse WafSecurityEvent) AttackEvents() []*api.AttackEvent {
	var events []*api.AttackEvent
	for _, attack := range wse {
		e, err := fromWAFAttack(attack.Time, attack.Block, attack.Metadata)
		if err != nil {
			//TODO(kyle): Figure out what to do with this error
		}
		events = append(events, e...)
	}
	return events
}

// fromWAFAttack creates the attack event payloads from a WAF attack.
func fromWAFAttack(t time.Time, blocked bool, md []byte) (events []*api.AttackEvent, err error) {
	var matches AttackMetadata
	if err := json.Unmarshal(md, &matches); err != nil {
		return nil, err
	}
	// Create one security event per flow and per filter
	for _, match := range matches {
		rule := &api.AttackRule{
			ID:   match.Rule,
			Name: match.Flow,
		}
		for _, filter := range match.Filter {
			ruleMatch := &api.AttackRuleMatch{
				Operator:      filter.Operator,
				OperatorValue: filter.OperatorValue,
				Parameters: []api.AttackRuleMatchParameter{
					{
						Name:  filter.BindingAccessor,
						Value: filter.ResolvedValue,
					},
				},
				Highlight: []string{filter.MatchStatus},
			}
			events = append(events, api.NewAttackEvent(match.Flow, blocked, t, rule, ruleMatch, nil))
		}
	}
	return events, nil
}

// List of rule addresses currently supported by the WAF
const (
	ServerRequestRawURIAddr  = "server.request.uri.raw"
	ServerRequestHeadersAddr = "server.request.headers.no_cookies"
)

func runWAF(wafCtx types.Rule, values types.DataSet, attacks *[]RawAttackMetadata) {
	action, md, err := wafCtx.Run(values, 1*time.Millisecond)
	if err != nil {
		log.Error("appsec: waf error: %v", err)
		return
	}
	if action == types.NoAction {
		return
	}
	*attacks = append(*attacks, RawAttackMetadata{Time: time.Now(), Block: action == types.BlockAction, Metadata: md})
}
