package vault

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (p *Plugin) subscribe(ctx context.Context) (subscription chan struct{}) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	if p.subscription == nil {
		p.subscription = make(chan struct{})
		go func() {
			defer p.stopWatching()
			p.startWatching(ctx, p.subscription)
		}()
	}

	return p.subscription
}

func (p *Plugin) stopWatching() {
	close(p.subscription)
	p.subscription = nil
}

func (p *Plugin) startWatching(ctx context.Context, subscription chan<- struct{}) {
	t := time.NewTicker(p.vaultPollFrequency)
	defer t.Stop()
	for subscription != nil {
		upstreamRoot, err := p.fetchUpstreamRoot(ctx)
		if err != nil {
			p.logger.Error("error fetching upstream roots from vault - error - ", err)
		}
		if upstreamRoot == nil {
			p.logger.Error("Upstream root fetched is nil")
		}

		if isRenewed(upstreamRoot, p.upstreamRoot) {
			p.logger.Debug("root CA renewed, does not match existing..")
			subscription <- struct{}{}
		}

		select {
		case <-ctx.Done():
			p.logger.Warn(ctx.Err().Error())
			return
		case <-t.C:
		}
	}
}

func (p *Plugin) fetchUpstreamRoot(ctx context.Context) (upstreamRoot *x509.Certificate, err error) {
	p.logger.Debug("starting fetch upstream root...")
	response, err := p.vc.FetchRoot(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error fetching upstream roots: %v", err)
	}

	upstreamRoot, err = pemutil.ParseCertificate([]byte(response.UpstreamCACertPEM))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse Root CA certificate: %v", err)
	}
	p.logger.Debug("serial for upstream root fetched : ", upstreamRoot.SerialNumber)
	return upstreamRoot, nil
}

func isRenewed(updated *x509.Certificate, current *x509.Certificate) bool {
	if current == nil {
		return true
	}
	if updated == nil {
		return false
	}
	return updated.SerialNumber.Cmp(current.SerialNumber) != 0
}
