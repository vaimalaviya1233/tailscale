// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package kubestore contains an ipn.StateStore implementation using Kubernetes Secrets.
package kubestore

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
)

const (
	// timeout is the timeout for a single state update that includes calls to the API server to write or read a
	// state Secret and emit an Event.
	timeout = 30 * time.Second

	reasonTailscaleStateUpdated      = "TailscaledStateUpdated"
	reasonTailscaleStateLoaded       = "TailscaleStateLoaded"
	reasonTailscaleStateUpdateFailed = "TailscaleStateUpdateFailed"
	reasonTailscaleStateLoadFailed   = "TailscaleStateLoadFailed"
	eventTypeWarning                 = "Warning"
	eventTypeNormal                  = "Normal"
)

// Store is an ipn.StateStore that uses a Kubernetes Secret for persistence.
type Store struct {
	client     kubeclient.Client
	canPatch   bool
	secretName string

	// memory holds the latest tailscale state. Writes write state to a kube Secret and memory, Reads read from
	// memory.
	memory mem.Store

	// knownDomains tracks which domains we know about
	// TODO: would map[string]bool be more efficient?
	knownDomains []string
}

// New returns a new Store that persists to the named Secret.
func New(logf logger.Logf, secretName string) (*Store, error) {
	c, err := kubeclient.New("tailscale-state-store")
	if err != nil {
		return nil, err
	}
	if os.Getenv("TS_KUBERNETES_READ_API_SERVER_ADDRESS_FROM_ENV") == "true" {
		// Derive the API server address from the environment variables
		c.SetURL(fmt.Sprintf("https://%s:%s", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")))
	}
	canPatch, _, err := c.CheckSecretPermissions(context.Background(), secretName)
	if err != nil {
		return nil, err
	}
	s := &Store{
		client:     c,
		canPatch:   canPatch,
		secretName: secretName,
	}
	// Load latest state from kube Secret if it already exists.
	if err := s.loadState(); err != nil && err != ipn.ErrStateNotExist {
		return nil, fmt.Errorf("error loading state from kube Secret: %w", err)
	}

	// If we are in cert share mode, load pre-existing certs.
	if envknob.IsCertShareReadOnlyMode() || envknob.IsCertShareReadWriteMode() {
		log.Printf("looking up pre-existing cert Secrets")
		sel := certSecretSelectorForHAIngress()
		ss, err := c.ListSecrets(context.Background(), sel)
		if err != nil {
			return nil, fmt.Errorf("error loading cert Secrets to cache: %w", err)
		}
		for _, secret := range ss.Items {
			log.Printf("loading cert and key from Secret %q", secret.Name)
			s.memory.WriteState(ipn.StateKey(secret.Name)+".crt", secret.Data["tls.crt"])
			s.memory.WriteState(ipn.StateKey(secret.Name)+".key", secret.Data["tls.key"])
		}
		// If we are in cert share read-only mode, ensure that we periodically reload certs, so that if they
		// were renewed by the leader replica, we get the updated version.
		if envknob.IsCertShareReadOnlyMode() {
			log.Printf("kubestore: starting periodic cert refresh from Secrets")
			go s.refreshCertsFromSecrets(context.Background(), logf)
		}
	}
	return s, nil
}

func (s *Store) SetDialer(d func(ctx context.Context, network, address string) (net.Conn, error)) {
	s.client.SetDialer(d)
}

func (s *Store) String() string { return "kube.Store" }

// ReadState implements the StateStore interface.
func (s *Store) ReadState(id ipn.StateKey) ([]byte, error) {
	return s.memory.ReadState(ipn.StateKey(sanitizeKey(id)))
}

// WriteState implements the StateStore interface.
func (s *Store) WriteState(id ipn.StateKey, bs []byte) (err error) {
	return s.updateSecret(map[string][]byte{string(id): bs}, s.secretName, nil)
}

// WriteTLSCertAndKey writes a TLS cert and key to domain.crt, domain.key fields
// to a Kubernetes Secret.
func (s *Store) WriteTLSCertAndKey(domain string, cert, key []byte) error {
	log.Printf("kubestore: writing cert and key for %q", domain)
	// If we run in cert share mode, cert and key for a DNS name are written
	// to a separate Secret.
	if envknob.IsCertShareReadWriteMode() {
		secretName := sanitizeKey(domain)
		labels := certSecretSelectorForHAIngress()
		return s.updateSecret(map[string][]byte{"tls.crt": cert, "tls.key": key}, secretName, labels)
	}
	return s.updateSecret(map[string][]byte{domain + ".crt": cert, domain + ".key": key}, s.secretName, nil)
}

// ReadTLSCertAndKey reads a TLS cert and key from memory or from a
// domain-specific Secret. It first checks the in-memory store, if not found in
// memory and running cert store in read-only mode, looks up a Secret.
func (s *Store) ReadTLSCertAndKey(domain string) (cert, key []byte, err error) {
	log.Printf("kubestore: reading cert and key for %q", domain)
	// Try memory first - use sanitized keys
	certKey := sanitizeKey(domain + ".crt")
	keyKey := sanitizeKey(domain + ".key")

	cert, err = s.memory.ReadState(ipn.StateKey(certKey))
	if err == nil {
		key, err = s.memory.ReadState(ipn.StateKey(keyKey))
		if err == nil {
			log.Printf("kubestore: found cert and key for %q in memory", domain)
			return cert, key, nil
		}
	}
	if !envknob.IsCertShareReadOnlyMode() {
		return nil, nil, ipn.ErrStateNotExist
	}

	// Not in memory, try loading from Secret
	secretName := sanitizeKey(domain)
	log.Printf("kubestore: attempting to load cert and key for %q from Secret %q", domain, secretName)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	secret, err := s.client.GetSecret(ctx, secretName)
	if err != nil {
		if kubeclient.IsNotFoundErr(err) {
			log.Printf("kubestore: Secret %q not found for domain %q", secretName, domain)
			return nil, nil, ipn.ErrStateNotExist
		}
		log.Printf("kubestore: error getting Secret %q: %v", secretName, err)
		return nil, nil, fmt.Errorf("getting TLS Secret %q: %w", secretName, err)
	}

	// TODO: double check with cert-manager for what is standard name
	cert = secret.Data["tls.crt"]
	key = secret.Data["tls.key"]
	if len(cert) == 0 || len(key) == 0 {
		log.Printf("kubestore: Secret %q exists but missing cert or key for domain %q", secretName, domain)
		return nil, nil, ipn.ErrStateNotExist
	}

	log.Printf("kubestore: successfully loaded cert and key from Secret %q for domain %q", secretName, domain)

	// Cache in memory for future reads
	s.memory.WriteState(ipn.StateKey(certKey), cert)
	s.memory.WriteState(ipn.StateKey(keyKey), key)

	// Add to known domains since we successfully read from Secret
	s.knownDomains = append(s.knownDomains, domain)

	return cert, key, nil
}

func (s *Store) updateSecret(data map[string][]byte, secretName string, labels map[string]string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer func() {
		if err == nil {
			for id, bs := range data {
				// The in-memory store does not distinguish between values read from state Secret on
				// init and values written to afterwards. Values read from the state
				// Secret will always be sanitized, so we also need to sanitize values written to store
				// later, so that the Read logic can just lookup keys in sanitized form.
				s.memory.WriteState(ipn.StateKey(sanitizeKey(id)), bs)
			}
		}
		if err != nil {
			if err := s.client.Event(ctx, eventTypeWarning, reasonTailscaleStateUpdateFailed, err.Error()); err != nil {
				log.Printf("kubestore: error creating tailscaled state update Event: %v", err)
			}
		} else {
			if err := s.client.Event(ctx, eventTypeNormal, reasonTailscaleStateUpdated, "Successfully updated tailscaled state Secret"); err != nil {
				log.Printf("kubestore: error creating tailscaled state Event: %v", err)
			}
		}
		cancel()
	}()
	secret, err := s.client.GetSecret(ctx, secretName)
	if err != nil {
		// If the Secret does not exist, create it with the required data.
		if kubeclient.IsNotFoundErr(err) {
			return s.client.CreateSecret(ctx, &kubeapi.Secret{
				TypeMeta: kubeapi.TypeMeta{
					APIVersion: "v1",
					Kind:       "Secret",
				},
				ObjectMeta: kubeapi.ObjectMeta{
					Name:   secretName,
					Labels: labels,
				},
				Data: func(m map[string][]byte) map[string][]byte {
					d := make(map[string][]byte, len(m))
					for key, val := range m {
						d[sanitizeKey(key)] = val
					}
					return d
				}(data),
			})
		}
		return err
	}
	if s.canPatch {
		var m []kubeclient.JSONPatch
		// If the user has pre-created a Secret with no data, we need to ensure the top level /data field.
		if len(secret.Data) == 0 {
			m = []kubeclient.JSONPatch{
				{
					Op:   "add",
					Path: "/data",
					Value: func(m map[string][]byte) map[string][]byte {
						d := make(map[string][]byte, len(m))
						for key, val := range m {
							d[sanitizeKey(key)] = val
						}
						return d
					}(data),
				},
			}
			// If the Secret has data, patch it with the new data.
		} else {
			for key, val := range data {
				m = append(m, kubeclient.JSONPatch{
					Op:    "add",
					Path:  "/data/" + sanitizeKey(key),
					Value: val,
				})
			}
		}
		if err := s.client.JSONPatchResource(ctx, s.secretName, kubeclient.TypeSecrets, m); err != nil {
			return fmt.Errorf("error patching Secret %s: %w", s.secretName, err)
		}
		return nil
	}
	// No patch permissions, use UPDATE instead.
	for key, val := range data {
		mak.Set(&secret.Data, sanitizeKey(key), val)
	}
	if err := s.client.UpdateSecret(ctx, secret); err != nil {
		return err
	}
	return err
}

func (s *Store) loadState() (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	secret, err := s.client.GetSecret(ctx, s.secretName)
	if err != nil {
		if st, ok := err.(*kubeapi.Status); ok && st.Code == 404 {
			return ipn.ErrStateNotExist
		}
		if err := s.client.Event(ctx, eventTypeWarning, reasonTailscaleStateLoadFailed, err.Error()); err != nil {
			log.Printf("kubestore: error creating Event: %v", err)
		}
		return err
	}
	if err := s.client.Event(ctx, eventTypeNormal, reasonTailscaleStateLoaded, "Successfully loaded tailscaled state from Secret"); err != nil {
		log.Printf("kubestore: error creating Event: %v", err)
	}
	s.memory.LoadFromMap(secret.Data)
	return nil
}

// sanitizeKey converts any value that can be converted to a string into a valid Kubernetes Secret key.
// Valid characters are alphanumeric, -, _, and .
// https://kubernetes.io/docs/concepts/configuration/secret/#restriction-names-data.
func sanitizeKey[T ~string](k T) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, string(k))
}

// refreshCertsFromSecrets periodically refreshes all TLS certificates stored in memory
// by looking up their corresponding Secrets.
func (s *Store) refreshCertsFromSecrets(ctx context.Context, logf logger.Logf) {
	logf("kubestore: starting periodic cert refresh from Secrets")
	// TODO: daily?
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logf("kubestore: stopping cert refresh")
			return
		case <-ticker.C:
			logf("kubestore: starting daily cert refresh")
			// Get all domains that have valid certs in memory
			var validDomains []string
			for _, domain := range s.knownDomains {
				if _, err := s.memory.ReadState(ipn.StateKey(sanitizeKey(domain + ".crt"))); err == nil {
					validDomains = append(validDomains, domain)
				}
			}
			logf("kubestore: refreshing certs for %d domains", len(validDomains))

			// Refresh each cert/key pair
			for _, domain := range validDomains {
				secretName := sanitizeKey(domain)
				ctx, cancel := context.WithTimeout(context.Background(), timeout)

				secret, err := s.client.GetSecret(ctx, secretName)
				if err != nil {
					logf("kubestore: error refreshing cert for %q: %v", domain, err)
					cancel()
					continue
				}

				cert := secret.Data["tls.crt"]
				key := secret.Data["tls.key"]
				if len(cert) == 0 || len(key) == 0 {
					logf("kubestore: missing cert or key in Secret %q", secretName)
					cancel()
					continue
				}

				// Update memory store with refreshed values
				certKey := sanitizeKey(domain + ".crt")
				keyKey := sanitizeKey(domain + ".key")
				s.memory.WriteState(ipn.StateKey(certKey), cert)
				s.memory.WriteState(ipn.StateKey(keyKey), key)

				logf("kubestore: refreshed certificate for %q from Secret", domain)
				cancel()
			}
		}
	}
}

func certSecretSelectorForHAIngress() map[string]string {
	podName := os.Getenv("POD_NAME")
	if podName == "" {
		return map[string]string{}
	}
	p := strings.LastIndex(podName, "-")
	if p == -1 {
		return map[string]string{}
	}
	pgName := podName[:p]
	return map[string]string{
		"tailscale.com/proxy-group": pgName,
		"tailscale.com/secret-type": "certs",
		"tailscale.com/managed":     "true"}
}
