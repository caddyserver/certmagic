// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/mholt/acmez/v2/acme"
	"go.uber.org/zap"
	"golang.org/x/crypto/ocsp"
)

// maintainAssets is a permanently-blocking function
// that loops indefinitely and, on a regular schedule, checks
// certificates for expiration and initiates a renewal of certs
// that are expiring soon. It also updates OCSP stapling. It
// should only be called once per cache. Panics are recovered,
// and if panicCount < 10, the function is called recursively,
// incrementing panicCount each time. Initial invocation should
// start panicCount at 0.
func (certCache *Cache) maintainAssets(panicCount int) {
	log := certCache.logger.Named("maintenance")
	log = log.With(zap.String("cache", fmt.Sprintf("%p", certCache)))

	defer func() {
		if err := recover(); err != nil {
			buf := make([]byte, stackTraceBufferSize)
			buf = buf[:runtime.Stack(buf, false)]
			log.Error("panic", zap.Any("error", err), zap.ByteString("stack", buf))
			if panicCount < 10 {
				certCache.maintainAssets(panicCount + 1)
			}
		}
	}()

	certCache.optionsMu.RLock()
	renewalTicker := time.NewTicker(certCache.options.RenewCheckInterval)
	ocspTicker := time.NewTicker(certCache.options.OCSPCheckInterval)
	certCache.optionsMu.RUnlock()

	log.Info("started background certificate maintenance")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for {
		select {
		case <-renewalTicker.C:
			err := certCache.RenewManagedCertificates(ctx)
			if err != nil {
				log.Error("renewing managed certificates", zap.Error(err))
			}
		case <-ocspTicker.C:
			certCache.updateOCSPStaples(ctx)
		case <-certCache.stopChan:
			renewalTicker.Stop()
			ocspTicker.Stop()
			log.Info("stopped background certificate maintenance")
			close(certCache.doneChan)
			return
		}
	}
}

// RenewManagedCertificates renews managed certificates,
// including ones loaded on-demand. Note that this is done
// automatically on a regular basis; normally you will not
// need to call this. This method assumes non-interactive
// mode (i.e. operating in the background).
func (certCache *Cache) RenewManagedCertificates(ctx context.Context) error {
	log := certCache.logger.Named("maintenance")

	// configs will hold a map of certificate hash to the config
	// to use when managing that certificate
	configs := make(map[string]*Config)

	// we use the queues for a very important reason: to do any and all
	// operations that could require an exclusive write lock outside
	// of the read lock! otherwise we get a deadlock, yikes. in other
	// words, our first iteration through the certificate cache does NOT
	// perform any operations--only queues them--so that more fine-grained
	// write locks may be obtained during the actual operations.
	var renewQueue, reloadQueue, deleteQueue, ariQueue certList

	certCache.mu.RLock()
	for certKey, cert := range certCache.cache {
		if !cert.managed {
			continue
		}

		// the list of names on this cert should never be empty... programmer error?
		if cert.Names == nil || len(cert.Names) == 0 {
			log.Warn("certificate has no names; removing from cache", zap.String("cert_key", certKey))
			deleteQueue = append(deleteQueue, cert)
			continue
		}

		// get the config associated with this certificate
		cfg, err := certCache.getConfig(cert)
		if err != nil {
			log.Error("unable to get configuration to manage certificate; unable to renew",
				zap.Strings("identifiers", cert.Names),
				zap.Error(err))
			continue
		}
		if cfg == nil {
			// this is bad if this happens, probably a programmer error (oops)
			log.Error("no configuration associated with certificate; unable to manage",
				zap.Strings("identifiers", cert.Names))
			continue
		}
		if cfg.OnDemand != nil {
			continue
		}

		// ACME-specific: see if if ACME Renewal Info (ARI) window needs refreshing
		if !cfg.DisableARI && cert.ari.NeedsRefresh() {
			configs[cert.hash] = cfg
			ariQueue = append(ariQueue, cert)
		}

		// if time is up or expires soon, we need to try to renew it
		if cert.NeedsRenewal(cfg) {
			configs[cert.hash] = cfg

			// see if the certificate in storage has already been renewed, possibly by another
			// instance that didn't coordinate with this one; if so, just load it (this
			// might happen if another instance already renewed it - kinda sloppy but checking disk
			// first is a simple way to possibly drastically reduce rate limit problems)
			storedCertNeedsRenew, err := cfg.managedCertInStorageNeedsRenewal(ctx, cert)
			if err != nil {
				// hmm, weird, but not a big deal, maybe it was deleted or something
				log.Warn("error while checking if stored certificate is also expiring soon",
					zap.Strings("identifiers", cert.Names),
					zap.Error(err))
			} else if !storedCertNeedsRenew {
				// if the certificate does NOT need renewal and there was no error, then we
				// are good to just reload the certificate from storage instead of repeating
				// a likely-unnecessary renewal procedure
				reloadQueue = append(reloadQueue, cert)
				continue
			}

			// the certificate in storage has not been renewed yet, so we will do it
			// NOTE: It is super-important to note that the TLS-ALPN challenge requires
			// a write lock on the cache in order to complete its challenge, so it is extra
			// vital that this renew operation does not happen inside our read lock!
			renewQueue.insert(cert)
		}
	}
	certCache.mu.RUnlock()

	// Update ARI, and then for any certs where the ARI window changed,
	// be sure to queue them for renewal if necessary
	for _, cert := range ariQueue {
		cfg := configs[cert.hash]
		cert, changed, err := cfg.updateARI(ctx, cert, log)
		if err != nil {
			log.Error("updating ARI", zap.Error(err))
		}
		if changed && cert.NeedsRenewal(cfg) {
			// it's theoretically possible that another instance already got the memo
			// on the changed ARI and even renewed the cert already, and thus doing it
			// here is wasteful, but I have never heard of this happening in reality,
			// so to save some cycles for now I think we'll just queue it for renewal
			// (notice how we use 'insert' to avoid duplicates, in case it was already
			// scheduled for renewal anyway)
			renewQueue.insert(cert)
		}
	}

	// Reload certificates that merely need to be updated in memory
	for _, oldCert := range reloadQueue {
		timeLeft := expiresAt(oldCert.Leaf).Sub(time.Now().UTC())
		log.Info("certificate expires soon, but is already renewed in storage; reloading stored certificate",
			zap.Strings("identifiers", oldCert.Names),
			zap.Duration("remaining", timeLeft))

		cfg := configs[oldCert.hash]

		// crucially, this happens OUTSIDE a lock on the certCache
		_, err := cfg.reloadManagedCertificate(ctx, oldCert)
		if err != nil {
			log.Error("loading renewed certificate",
				zap.Strings("identifiers", oldCert.Names),
				zap.Error(err))
			continue
		}
	}

	// Renewal queue
	for _, oldCert := range renewQueue {
		cfg := configs[oldCert.hash]
		err := certCache.queueRenewalTask(ctx, oldCert, cfg)
		if err != nil {
			log.Error("queueing renewal task",
				zap.Strings("identifiers", oldCert.Names),
				zap.Error(err))
			continue
		}
	}

	// Deletion queue
	certCache.mu.Lock()
	for _, cert := range deleteQueue {
		certCache.removeCertificate(cert)
	}
	certCache.mu.Unlock()

	return nil
}

func (certCache *Cache) queueRenewalTask(ctx context.Context, oldCert Certificate, cfg *Config) error {
	log := certCache.logger.Named("maintenance")

	timeLeft := expiresAt(oldCert.Leaf).Sub(time.Now().UTC())
	log.Info("certificate expires soon; queuing for renewal",
		zap.Strings("identifiers", oldCert.Names),
		zap.Duration("remaining", timeLeft))

	// Get the name which we should use to renew this certificate;
	// we only support managing certificates with one name per cert,
	// so this should be easy.
	renewName := oldCert.Names[0]

	// queue up this renewal job (is a no-op if already active or queued)
	jm.Submit(cfg.Logger, "renew_"+renewName, func() error {
		timeLeft := expiresAt(oldCert.Leaf).Sub(time.Now().UTC())
		log.Info("attempting certificate renewal",
			zap.Strings("identifiers", oldCert.Names),
			zap.Duration("remaining", timeLeft))

		// perform renewal - crucially, this happens OUTSIDE a lock on certCache
		err := cfg.RenewCertAsync(ctx, renewName, false)
		if err != nil {
			if cfg.OnDemand != nil {
				// loaded dynamically, remove dynamically
				certCache.mu.Lock()
				certCache.removeCertificate(oldCert)
				certCache.mu.Unlock()
			}
			return fmt.Errorf("%v %v", oldCert.Names, err)
		}

		// successful renewal, so update in-memory cache by loading
		// renewed certificate so it will be used with handshakes
		_, err = cfg.reloadManagedCertificate(ctx, oldCert)
		if err != nil {
			return ErrNoRetry{fmt.Errorf("%v %v", oldCert.Names, err)}
		}
		return nil
	})

	return nil
}

// updateOCSPStaples updates the OCSP stapling in all
// eligible, cached certificates.
//
// OCSP maintenance strives to abide the relevant points on
// Ryan Sleevi's recommendations for good OCSP support:
// https://gist.github.com/sleevi/5efe9ef98961ecfb4da8
func (certCache *Cache) updateOCSPStaples(ctx context.Context) {
	logger := certCache.logger.Named("maintenance")

	// temporary structures to store updates or tasks
	// so that we can keep our locks short-lived
	type ocspUpdate struct {
		rawBytes []byte
		parsed   *ocsp.Response
	}
	type updateQueueEntry struct {
		cert           Certificate
		certHash       string
		lastNextUpdate time.Time
		cfg            *Config
	}
	type renewQueueEntry struct {
		oldCert Certificate
		cfg     *Config
	}
	updated := make(map[string]ocspUpdate)
	var updateQueue []updateQueueEntry // certs that need a refreshed staple
	var renewQueue []renewQueueEntry   // certs that need to be renewed (due to revocation)

	// obtain brief read lock during our scan to see which staples need updating
	certCache.mu.RLock()
	for certHash, cert := range certCache.cache {
		// no point in updating OCSP for expired or "synthetic" certificates
		if cert.Leaf == nil || cert.Expired() {
			continue
		}
		cfg, err := certCache.getConfig(cert)
		if err != nil {
			logger.Error("unable to get automation config for certificate; maintenance for this certificate will likely fail",
				zap.Strings("identifiers", cert.Names),
				zap.Error(err))
			continue
		}
		// always try to replace revoked certificates, even if OCSP response is still fresh
		if certShouldBeForceRenewed(cert) {
			renewQueue = append(renewQueue, renewQueueEntry{
				oldCert: cert,
				cfg:     cfg,
			})
			continue
		}
		// if the status is not fresh, get a new one
		var lastNextUpdate time.Time
		if cert.ocsp != nil {
			lastNextUpdate = cert.ocsp.NextUpdate
			if cert.ocsp.Status != ocsp.Unknown && freshOCSP(cert.ocsp) {
				// no need to update our staple if still fresh and not Unknown
				continue
			}
		}
		updateQueue = append(updateQueue, updateQueueEntry{cert, certHash, lastNextUpdate, cfg})
	}
	certCache.mu.RUnlock()

	// perform updates outside of any lock on certCache
	for _, qe := range updateQueue {
		cert := qe.cert
		certHash := qe.certHash
		lastNextUpdate := qe.lastNextUpdate

		if qe.cfg == nil {
			// this is bad if this happens, probably a programmer error (oops)
			logger.Error("no configuration associated with certificate; unable to manage OCSP staples",
				zap.Strings("identifiers", cert.Names))
			continue
		}

		err := stapleOCSP(ctx, qe.cfg.OCSP, qe.cfg.Storage, &cert, nil)
		if err != nil {
			if cert.ocsp != nil {
				// if there was no staple before, that's fine; otherwise we should log the error
				logger.Error("stapling OCSP",
					zap.Strings("identifiers", cert.Names),
					zap.Error(err))
			}
			continue
		}

		// By this point, we've obtained the latest OCSP response.
		// If there was no staple before, or if the response is updated, make
		// sure we apply the update to all names on the certificate if
		// the status is still Good.
		if cert.ocsp != nil && cert.ocsp.Status == ocsp.Good && (lastNextUpdate.IsZero() || lastNextUpdate != cert.ocsp.NextUpdate) {
			logger.Info("advancing OCSP staple",
				zap.Strings("identifiers", cert.Names),
				zap.Time("from", lastNextUpdate),
				zap.Time("to", cert.ocsp.NextUpdate))
			updated[certHash] = ocspUpdate{rawBytes: cert.Certificate.OCSPStaple, parsed: cert.ocsp}
		}

		// If the updated staple shows that the certificate was revoked, we should immediately renew it
		if certShouldBeForceRenewed(cert) {
			qe.cfg.emit(ctx, "cert_ocsp_revoked", map[string]any{
				"subjects":    cert.Names,
				"certificate": cert,
				"reason":      cert.ocsp.RevocationReason,
				"revoked_at":  cert.ocsp.RevokedAt,
			})

			renewQueue = append(renewQueue, renewQueueEntry{
				oldCert: cert,
				cfg:     qe.cfg,
			})
		}
	}

	// These write locks should be brief since we have all the info we need now.
	for certKey, update := range updated {
		certCache.mu.Lock()
		if cert, ok := certCache.cache[certKey]; ok {
			cert.ocsp = update.parsed
			cert.Certificate.OCSPStaple = update.rawBytes
			certCache.cache[certKey] = cert
		}
		certCache.mu.Unlock()
	}

	// We attempt to replace any certificates that were revoked.
	// Crucially, this happens OUTSIDE a lock on the certCache.
	for _, renew := range renewQueue {
		_, err := renew.cfg.forceRenew(ctx, logger, renew.oldCert)
		if err != nil {
			logger.Info("forcefully renewing certificate due to REVOKED status",
				zap.Strings("identifiers", renew.oldCert.Names),
				zap.Error(err))
		}
	}
}

// storageHasNewerARI returns true if the configured storage has ARI that is newer
// than that of a certificate that is already loaded, along with the value from
// storage.
func (cfg *Config) storageHasNewerARI(ctx context.Context, cert Certificate) (bool, acme.RenewalInfo, error) {
	storedCertData, err := cfg.loadStoredACMECertificateMetadata(ctx, cert)
	if err != nil || storedCertData.RenewalInfo == nil {
		return false, acme.RenewalInfo{}, err
	}
	// prefer stored info if it has a window and the loaded one doesn't,
	// or if the one in storage has a later RetryAfter (though I suppose
	// it's not guaranteed, typically those will move forward in time)
	if (!cert.ari.HasWindow() && storedCertData.RenewalInfo.HasWindow()) ||
		(cert.ari.RetryAfter == nil || storedCertData.RenewalInfo.RetryAfter.After(*cert.ari.RetryAfter)) {
		return true, *storedCertData.RenewalInfo, nil
	}
	return false, acme.RenewalInfo{}, nil
}

// loadStoredACMECertificateMetadata loads the stored ACME certificate data
// from the cert's sidecar JSON file.
func (cfg *Config) loadStoredACMECertificateMetadata(ctx context.Context, cert Certificate) (acme.Certificate, error) {
	metaBytes, err := cfg.Storage.Load(ctx, StorageKeys.SiteMeta(cert.issuerKey, cert.Names[0]))
	if err != nil {
		return acme.Certificate{}, fmt.Errorf("loading cert metadata: %w", err)
	}

	var certRes CertificateResource
	if err = json.Unmarshal(metaBytes, &certRes); err != nil {
		return acme.Certificate{}, fmt.Errorf("unmarshaling cert metadata: %w", err)
	}

	var acmeCert acme.Certificate
	if err = json.Unmarshal(certRes.IssuerData, &acmeCert); err != nil {
		return acme.Certificate{}, fmt.Errorf("unmarshaling potential ACME issuer metadata: %v", err)
	}

	return acmeCert, nil
}

// updateARI updates the cert's ACME renewal info, first by checking storage for a newer
// one, or getting it from the CA if needed. The updated info is stored in storage and
// updated in the cache. The certificate with the updated ARI is returned. If true is
// returned, the ARI window or selected time has changed, and the caller should check if
// the cert needs to be renewed now, even if there is an error.
//
// This will always try to ARI without checking if it needs to be refreshed. Call
// NeedsRefresh() on the RenewalInfo first, and only call this if that returns true.
func (cfg *Config) updateARI(ctx context.Context, cert Certificate, logger *zap.Logger) (updatedCert Certificate, changed bool, err error) {
	logger = logger.With(
		zap.Strings("identifiers", cert.Names),
		zap.String("cert_hash", cert.hash),
		zap.String("ari_unique_id", cert.ari.UniqueIdentifier),
		zap.Time("cert_expiry", cert.Leaf.NotAfter))

	updatedCert = cert
	oldARI := cert.ari

	// synchronize ARI fetching; see #297
	lockName := "ari_" + cert.ari.UniqueIdentifier
	if err := acquireLock(ctx, cfg.Storage, lockName); err != nil {
		return cert, false, fmt.Errorf("unable to obtain ARI lock: %v", err)
	}
	defer func() {
		if err := releaseLock(ctx, cfg.Storage, lockName); err != nil {
			logger.Error("unable to release ARI lock", zap.Error(err))
		}
	}()

	// see if the stored value has been refreshed already by another instance
	gotNewARI, newARI, err := cfg.storageHasNewerARI(ctx, cert)

	// when we're all done, log if something about the schedule is different
	// ("WARN" level because ARI window changing may be a sign of external trouble
	// and we want to draw their attention to a potential explanation URL)
	defer func() {
		changed = !newARI.SameWindow(oldARI)

		if changed {
			logger.Warn("ARI window or selected renewal time changed",
				zap.Time("prev_start", oldARI.SuggestedWindow.Start),
				zap.Time("next_start", newARI.SuggestedWindow.Start),
				zap.Time("prev_end", oldARI.SuggestedWindow.End),
				zap.Time("next_end", newARI.SuggestedWindow.End),
				zap.Time("prev_selected_time", oldARI.SelectedTime),
				zap.Time("next_selected_time", newARI.SelectedTime),
				zap.String("explanation_url", newARI.ExplanationURL))
		}
	}()

	if err == nil && gotNewARI {
		// great, storage has a newer one we can use
		cfg.certCache.mu.Lock()
		updatedCert = cfg.certCache.cache[cert.hash]
		updatedCert.ari = newARI
		cfg.certCache.cache[cert.hash] = updatedCert
		cfg.certCache.mu.Unlock()
		logger.Info("reloaded ARI with newer one in storage",
			zap.Timep("next_refresh", newARI.RetryAfter),
			zap.Time("renewal_time", newARI.SelectedTime))
		return
	}

	if err != nil {
		logger.Error("error while checking storage for updated ARI; updating ARI now", zap.Error(err))
	}

	// of the issuers configured, hopefully one of them is the ACME CA we got the cert from
	for _, iss := range cfg.Issuers {
		if ariGetter, ok := iss.(RenewalInfoGetter); ok {
			newARI, err = ariGetter.GetRenewalInfo(ctx, cert) // be sure to use existing newARI variable so we can compare against old value in the defer
			if err != nil {
				// could be anything, but a common error might simply be the "wrong" ACME CA
				// (meaning, different from the one that issued the cert, thus the only one
				// that would have any ARI for it) if multiple ACME CAs are configured
				logger.Error("failed updating renewal info from ACME CA",
					zap.String("issuer", iss.IssuerKey()),
					zap.Error(err))
				continue
			}

			// when we get the latest ARI, the acme package will select a time within the window
			// for us; of course, since it's random, it's likely different from the previously-
			// selected time; but if the window doesn't change, there's no need to change the
			// selected time (the acme package doesn't know the previous window to know better)
			// ... so if the window hasn't changed we'll just put back the selected time
			if newARI.SameWindow(oldARI) && !oldARI.SelectedTime.IsZero() {
				newARI.SelectedTime = oldARI.SelectedTime
			}

			// then store the updated ARI (even if the window didn't change, the Retry-After
			// likely did) in cache and storage

			// be sure we get the cert from the cache while inside a lock to avoid logical races
			cfg.certCache.mu.Lock()
			updatedCert = cfg.certCache.cache[cert.hash]
			updatedCert.ari = newARI
			cfg.certCache.cache[cert.hash] = updatedCert
			cfg.certCache.mu.Unlock()

			// update the ARI value in storage
			var certData acme.Certificate
			certData, err = cfg.loadStoredACMECertificateMetadata(ctx, cert)
			if err != nil {
				err = fmt.Errorf("got new ARI from %s, but failed loading stored certificate metadata: %v", iss.IssuerKey(), err)
				return
			}
			certData.RenewalInfo = &newARI
			var certDataBytes, certResBytes []byte
			certDataBytes, err = json.Marshal(certData)
			if err != nil {
				err = fmt.Errorf("got new ARI from %s, but failed marshaling certificate ACME metadata: %v", iss.IssuerKey(), err)
				return
			}
			certResBytes, err = json.MarshalIndent(CertificateResource{
				SANs:       cert.Names,
				IssuerData: certDataBytes,
			}, "", "\t")
			if err != nil {
				err = fmt.Errorf("got new ARI from %s, but could not re-encode certificate metadata: %v", iss.IssuerKey(), err)
				return
			}
			if err = cfg.Storage.Store(ctx, StorageKeys.SiteMeta(cert.issuerKey, cert.Names[0]), certResBytes); err != nil {
				err = fmt.Errorf("got new ARI from %s, but could not store it with certificate metadata: %v", iss.IssuerKey(), err)
				return
			}

			logger.Info("updated ACME renewal information",
				zap.Time("selected_time", newARI.SelectedTime),
				zap.Timep("next_update", newARI.RetryAfter),
				zap.String("explanation_url", newARI.ExplanationURL))

			return
		}
	}

	err = fmt.Errorf("could not fully update ACME renewal info: either no issuer supporting ARI is configured for certificate, or all such failed (make sure the ACME CA that issued the certificate is configured)")
	return
}

// CleanStorageOptions specifies how to clean up a storage unit.
type CleanStorageOptions struct {
	// Optional custom logger.
	Logger *zap.Logger

	// Optional ID of the instance initiating the cleaning.
	InstanceID string

	// If set, cleaning will be skipped if it was performed
	// more recently than this interval.
	Interval time.Duration

	// Whether to clean cached OCSP staples.
	OCSPStaples bool

	// Whether to cleanup expired certificates, and if so,
	// how long to let them stay after they've expired.
	ExpiredCerts           bool
	ExpiredCertGracePeriod time.Duration
}

// CleanStorage removes assets which are no longer useful,
// according to opts.
func CleanStorage(ctx context.Context, storage Storage, opts CleanStorageOptions) error {
	const (
		lockName   = "storage_clean"
		storageKey = "last_clean.json"
	)

	if opts.Logger == nil {
		opts.Logger = defaultLogger.Named("clean_storage")
	}
	opts.Logger = opts.Logger.With(zap.Any("storage", storage))

	// storage cleaning should be globally exclusive
	if err := acquireLock(ctx, storage, lockName); err != nil {
		return fmt.Errorf("unable to acquire %s lock: %v", lockName, err)
	}
	defer func() {
		if err := releaseLock(ctx, storage, lockName); err != nil {
			opts.Logger.Error("unable to release lock", zap.Error(err))
			return
		}
	}()

	// cleaning should not happen more often than the interval
	if opts.Interval > 0 {
		lastCleanBytes, err := storage.Load(ctx, storageKey)
		if !errors.Is(err, fs.ErrNotExist) {
			if err != nil {
				return fmt.Errorf("loading last clean timestamp: %v", err)
			}

			var lastClean lastCleanPayload
			err = json.Unmarshal(lastCleanBytes, &lastClean)
			if err != nil {
				return fmt.Errorf("decoding last clean data: %v", err)
			}

			lastTLSClean := lastClean["tls"]
			if time.Since(lastTLSClean.Timestamp) < opts.Interval {
				nextTime := time.Now().Add(opts.Interval)
				opts.Logger.Info("storage cleaning happened too recently; skipping for now",
					zap.String("instance", lastTLSClean.InstanceID),
					zap.Time("try_again", nextTime),
					zap.Duration("try_again_in", time.Until(nextTime)),
				)
				return nil
			}
		}
	}

	opts.Logger.Info("cleaning storage unit")

	if opts.OCSPStaples {
		err := deleteOldOCSPStaples(ctx, storage, opts.Logger)
		if err != nil {
			opts.Logger.Error("deleting old OCSP staples", zap.Error(err))
		}
	}
	if opts.ExpiredCerts {
		err := deleteExpiredCerts(ctx, storage, opts.Logger, opts.ExpiredCertGracePeriod)
		if err != nil {
			opts.Logger.Error("deleting expired certificates staples", zap.Error(err))
		}
	}
	// TODO: delete stale locks?

	// update the last-clean time
	lastCleanBytes, err := json.Marshal(lastCleanPayload{
		"tls": lastCleaned{
			Timestamp:  time.Now(),
			InstanceID: opts.InstanceID,
		},
	})
	if err != nil {
		return fmt.Errorf("encoding last cleaned info: %v", err)
	}
	if err := storage.Store(ctx, storageKey, lastCleanBytes); err != nil {
		return fmt.Errorf("storing last clean info: %v", err)
	}

	return nil
}

type lastCleanPayload map[string]lastCleaned

type lastCleaned struct {
	Timestamp  time.Time `json:"timestamp"`
	InstanceID string    `json:"instance_id,omitempty"`
}

func deleteOldOCSPStaples(ctx context.Context, storage Storage, logger *zap.Logger) error {
	ocspKeys, err := storage.List(ctx, prefixOCSP, false)
	if err != nil {
		// maybe just hasn't been created yet; no big deal
		return nil
	}
	for _, key := range ocspKeys {
		// if context was cancelled, quit early; otherwise proceed
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		ocspBytes, err := storage.Load(ctx, key)
		if err != nil {
			logger.Error("while deleting old OCSP staples, unable to load staple file", zap.Error(err))
			continue
		}
		resp, err := ocsp.ParseResponse(ocspBytes, nil)
		if err != nil {
			// contents are invalid; delete it
			err = storage.Delete(ctx, key)
			if err != nil {
				logger.Error("purging corrupt staple file", zap.String("storage_key", key), zap.Error(err))
			}
			continue
		}
		if time.Now().After(resp.NextUpdate) {
			// response has expired; delete it
			err = storage.Delete(ctx, key)
			if err != nil {
				logger.Error("purging expired staple file", zap.String("storage_key", key), zap.Error(err))
			}
		}
	}
	return nil
}

func deleteExpiredCerts(ctx context.Context, storage Storage, logger *zap.Logger, gracePeriod time.Duration) error {
	issuerKeys, err := storage.List(ctx, prefixCerts, false)
	if err != nil {
		// maybe just hasn't been created yet; no big deal
		return nil
	}

	for _, issuerKey := range issuerKeys {
		siteKeys, err := storage.List(ctx, issuerKey, false)
		if err != nil {
			logger.Error("listing contents", zap.String("issuer_key", issuerKey), zap.Error(err))
			continue
		}

		for _, siteKey := range siteKeys {
			// if context was cancelled, quit early; otherwise proceed
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			siteAssets, err := storage.List(ctx, siteKey, false)
			if err != nil {
				logger.Error("listing site contents", zap.String("site_key", siteKey), zap.Error(err))
				continue
			}

			for _, assetKey := range siteAssets {
				if path.Ext(assetKey) != ".crt" {
					continue
				}

				certFile, err := storage.Load(ctx, assetKey)
				if err != nil {
					return fmt.Errorf("loading certificate file %s: %v", assetKey, err)
				}
				block, _ := pem.Decode(certFile)
				if block == nil || block.Type != "CERTIFICATE" {
					return fmt.Errorf("certificate file %s does not contain PEM-encoded certificate", assetKey)
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return fmt.Errorf("certificate file %s is malformed; error parsing PEM: %v", assetKey, err)
				}

				if expiredTime := time.Since(expiresAt(cert)); expiredTime >= gracePeriod {
					logger.Info("certificate expired beyond grace period; cleaning up",
						zap.String("asset_key", assetKey),
						zap.Duration("expired_for", expiredTime),
						zap.Duration("grace_period", gracePeriod))
					baseName := strings.TrimSuffix(assetKey, ".crt")
					for _, relatedAsset := range []string{
						assetKey,
						baseName + ".key",
						baseName + ".json",
					} {
						logger.Info("deleting asset because resource expired", zap.String("asset_key", relatedAsset))
						err := storage.Delete(ctx, relatedAsset)
						if err != nil {
							logger.Error("could not clean up asset related to expired certificate",
								zap.String("base_name", baseName),
								zap.String("related_asset", relatedAsset),
								zap.Error(err))
						}
					}
				}
			}

			// update listing; if folder is empty, delete it
			siteAssets, err = storage.List(ctx, siteKey, false)
			if err != nil {
				continue
			}
			if len(siteAssets) == 0 {
				logger.Info("deleting site folder because key is empty", zap.String("site_key", siteKey))
				err := storage.Delete(ctx, siteKey)
				if err != nil {
					return fmt.Errorf("deleting empty site folder %s: %v", siteKey, err)
				}
			}
		}
	}
	return nil
}

// forceRenew forcefully renews cert and replaces it in the cache, and returns the new certificate. It is intended
// for use primarily in the case of cert revocation. This MUST NOT be called within a lock on cfg.certCacheMu.
func (cfg *Config) forceRenew(ctx context.Context, logger *zap.Logger, cert Certificate) (Certificate, error) {
	if cert.ocsp != nil && cert.ocsp.Status == ocsp.Revoked {
		logger.Warn("OCSP status for managed certificate is REVOKED; attempting to replace with new certificate",
			zap.Strings("identifiers", cert.Names),
			zap.Time("expiration", expiresAt(cert.Leaf)))
	} else {
		logger.Warn("forcefully renewing certificate",
			zap.Strings("identifiers", cert.Names),
			zap.Time("expiration", expiresAt(cert.Leaf)))
	}

	renewName := cert.Names[0]

	// if revoked for key compromise, we can't be sure whether the storage of
	// the key is still safe; however, we KNOW the old key is not safe, and we
	// can only hope by the time of revocation that storage has been secured;
	// key management is not something we want to get into, but in this case
	// it seems prudent to replace the key - and since renewal requires reuse
	// of a prior key, we can't do a "renew" to replace the cert if we need a
	// new key, so we'll have to do an obtain instead
	var obtainInsteadOfRenew bool
	if cert.ocsp != nil && cert.ocsp.RevocationReason == acme.ReasonKeyCompromise {
		err := cfg.moveCompromisedPrivateKey(ctx, cert, logger)
		if err != nil {
			logger.Error("could not remove compromised private key from use",
				zap.Strings("identifiers", cert.Names),
				zap.String("issuer", cert.issuerKey),
				zap.Error(err))
		}
		obtainInsteadOfRenew = true
	}

	var err error
	if obtainInsteadOfRenew {
		err = cfg.ObtainCertAsync(ctx, renewName)
	} else {
		// notice that we force renewal; otherwise, it might see that the
		// certificate isn't close to expiring and return, but we really
		// need a replacement certificate! see issue #4191
		err = cfg.RenewCertAsync(ctx, renewName, true)
	}
	if err != nil {
		if cert.ocsp != nil && cert.ocsp.Status == ocsp.Revoked {
			// probably better to not serve a revoked certificate at all
			logger.Error("unable to obtain new to certificate after OCSP status of REVOKED; removing from cache",
				zap.Strings("identifiers", cert.Names),
				zap.Error(err))
			cfg.certCache.mu.Lock()
			cfg.certCache.removeCertificate(cert)
			cfg.certCache.mu.Unlock()
		}
		return cert, fmt.Errorf("unable to forcefully get new certificate for %v: %w", cert.Names, err)
	}

	return cfg.reloadManagedCertificate(ctx, cert)
}

// moveCompromisedPrivateKey moves the private key for cert to a ".compromised" file
// by copying the data to the new file, then deleting the old one.
func (cfg *Config) moveCompromisedPrivateKey(ctx context.Context, cert Certificate, logger *zap.Logger) error {
	privKeyStorageKey := StorageKeys.SitePrivateKey(cert.issuerKey, cert.Names[0])

	privKeyPEM, err := cfg.Storage.Load(ctx, privKeyStorageKey)
	if err != nil {
		return err
	}

	compromisedPrivKeyStorageKey := privKeyStorageKey + ".compromised"
	err = cfg.Storage.Store(ctx, compromisedPrivKeyStorageKey, privKeyPEM)
	if err != nil {
		// better safe than sorry: as a last resort, try deleting the key so it won't be reused
		cfg.Storage.Delete(ctx, privKeyStorageKey)
		return err
	}

	err = cfg.Storage.Delete(ctx, privKeyStorageKey)
	if err != nil {
		return err
	}

	logger.Info("removed certificate's compromised private key from use",
		zap.String("storage_path", compromisedPrivKeyStorageKey),
		zap.Strings("identifiers", cert.Names),
		zap.String("issuer", cert.issuerKey))

	return nil
}

// certShouldBeForceRenewed returns true if cert should be forcefully renewed
// (like if it is revoked according to its OCSP response).
func certShouldBeForceRenewed(cert Certificate) bool {
	return cert.managed &&
		len(cert.Names) > 0 &&
		cert.ocsp != nil &&
		cert.ocsp.Status == ocsp.Revoked
}

type certList []Certificate

// insert appends cert to the list if it is not already in the list.
// Efficiency: O(n)
func (certs *certList) insert(cert Certificate) {
	for _, c := range *certs {
		if c.hash == cert.hash {
			return
		}
	}
	*certs = append(*certs, cert)
}

const (
	// DefaultRenewCheckInterval is how often to check certificates for expiration.
	// Scans are very lightweight, so this can be semi-frequent. This default should
	// be smaller than <Minimum Cert Lifetime>*DefaultRenewalWindowRatio/3, which
	// gives certificates plenty of chance to be renewed on time.
	DefaultRenewCheckInterval = 10 * time.Minute

	// DefaultRenewalWindowRatio is how much of a certificate's lifetime becomes the
	// renewal window. The renewal window is the span of time at the end of the
	// certificate's validity period in which it should be renewed. A default value
	// of ~1/3 is pretty safe and recommended for most certificates.
	DefaultRenewalWindowRatio = 1.0 / 3.0

	// DefaultOCSPCheckInterval is how often to check if OCSP stapling needs updating.
	DefaultOCSPCheckInterval = 1 * time.Hour
)
