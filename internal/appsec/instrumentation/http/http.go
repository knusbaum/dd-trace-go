// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

package http

import (
	"net/http"

	"gopkg.in/DataDog/dd-trace-go.v1/internal/appsec"
	"gopkg.in/DataDog/dd-trace-go.v1/internal/appsec/intake/api"
	"gopkg.in/DataDog/dd-trace-go.v1/internal/appsec/internal/protection/waf"
	"gopkg.in/DataDog/dd-trace-go.v1/internal/log"
)

func DetectAttacks(req *http.Request) func(status int) *api.SecurityEvent {
	w, err := waf.NewWAF()
	if err != nil {
		log.Error("appsec: waf error: %v", err)
		return func(int) *api.SecurityEvent { return nil }
	}

	headers := req.Header.Clone()
	headers.Del("Cookie")
	// Pass data from the http request to WAF
	values := map[string]interface{}{
		waf.ServerRequestRawURIAddr:  req.RequestURI,
		waf.ServerRequestHeadersAddr: headers,
	}
	w.Run(values)

	// We can use operations in the future to capture
	// data events from other integrations.
	// 	op := dyngo.StartOperation(req,
	// 		WithDataListener(func(op, data interface{}) {
	// 			// Pass data to WAF
	// 		}))

	return func(status int) *api.SecurityEvent {
		// 		op.Finish()
		w.Close()
		if attacks := w.Attacks(); len(attacks) > 0 {
			e := api.NewSecurityEvent(waf.WafSecurityEvent(attacks), api.WithHTTP(req, status))
			appsec.SubmitSecurityEvent(e)
			return e
		}
		return nil
	}
}
