// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/util/goroutines"
)

type certManager struct {
	mu        sync.Mutex
	parentCtx context.Context
	certLoops map[string]context.CancelFunc
	lc        localClient
	tracker   goroutines.Tracker
}

func (cm *certManager) ensureCertLoops(ctx context.Context, sc *ipn.ServeConfig) error {
	log.Printf("ensuring cert loops for %d services", len(sc.Services))
	currentDomains := make(map[string]bool)
	for _, service := range sc.Services {
		for hostPort := range service.Web {
			domain := strings.Split(string(hostPort), ":")[0]
			currentDomains[domain] = true
		}
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()
	for domain := range currentDomains {
		log.Printf("ensuring cert loop for %s", domain)
		if _, exists := cm.certLoops[domain]; !exists {
			ctx, cancel := context.WithCancel(cm.parentCtx)

			cm.certLoops[domain] = cancel

			cm.tracker.Go(func() { cm.runCertLoop(ctx, domain) })
		}
	}

	// Cancel and remove goroutines for domains that are no longer in the config
	for domain, cancel := range cm.certLoops {
		if !currentDomains[domain] {
			cancel()
			delete(cm.certLoops, domain)
		}
	}
	return nil
}

func (cm *certManager) runCertLoop(ctx context.Context, domain string) {
	log.Printf("in goroutine: starting cert loop for %s", domain)
	const (
		normalInterval   = 24 * time.Hour
		initialRetry     = 1 * time.Minute
		maxRetryInterval = 24 * time.Hour
	)

	timer := time.NewTimer(0)
	defer timer.Stop()

	retryCount := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			log.Printf("refreshing certificate for %s", domain)
			_, _, err := cm.lc.CertPair(ctx, domain)
			if err != nil {
				log.Printf("error refreshing certificate for %s: %v", domain, err)
			}

			var nextInterval time.Duration
			if err == nil {
				retryCount = 0
				nextInterval = normalInterval
			} else {
				retryCount++
				// Calculate backoff: initialRetry * 2^(retryCount-1)
				// For retryCount=1: 1min * 2^0 = 1min
				// For retryCount=2: 1min * 2^1 = 2min
				// For retryCount=3: 1min * 2^2 = 4min
				backoff := initialRetry * time.Duration(1<<(retryCount-1))

				if backoff > maxRetryInterval {
					backoff = maxRetryInterval
				}
				nextInterval = backoff
				fmt.Printf("Error refreshing certificate for %s (retry %d): %v. Will retry in %v\n",
					domain, retryCount, err, nextInterval)
			}
			timer.Reset(nextInterval)
		}
	}
}
