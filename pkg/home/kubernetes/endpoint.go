package kubernetes

import (
	"net/netip"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/helayoty/fiberd/pkg/endpoint"
)

// How long EndpointHost waits for the kubelet to write the Pod's address,
// and how often it reads the Pod meanwhile.
const (
	podIPWait  = 90 * time.Second
	podIPRetry = time.Second
)

// EndpointHost is the Pod's IP of the configured family. The last Pod
// stored is consulted first. fiberd asks before Run, and PID 1 can start
// before the kubelet has written the address, so the home then reads the
// Pod every podIPRetry for up to podIPWait. Close, or Run's context
// ending, cuts the wait short. It returns "" when the Pod has no address
// of that family in time, and logs the last read error once when it
// gives up. The unix family advertises no address, so it returns "" at
// once.
func (h *Home) EndpointHost() string {
	want := h.cfg.Family
	if want != endpoint.Inet4 && want != endpoint.Inet6 {
		return ""
	}
	h.mu.Lock()
	self := h.self
	h.mu.Unlock()
	if self != nil {
		if ip := podIP(self, want); ip != "" {
			return ip
		}
	}
	start := h.cfg.Clock.Now()
	var lastErr error
	for {
		p, err := h.cfg.Kube.GetPod(h.stopCtx, h.cfg.PodNamespace, h.cfg.PodName)
		lastErr = err
		if err == nil {
			if ip := podIP(p, want); ip != "" {
				return ip
			}
		}
		if h.stopCtx.Err() != nil {
			h.log.Info("Stopped before the Pod had an address", "family", want)
			return ""
		}
		if h.cfg.Clock.Since(start) >= podIPWait {
			break
		}
		select {
		case <-h.stopCtx.Done():
			h.log.Info("Stopped before the Pod had an address", "family", want)
			return ""
		case <-h.cfg.Clock.After(podIPRetry):
		}
	}
	if lastErr != nil {
		h.log.Error(lastErr, "Gave up waiting for the Pod's address", "family", want, "waited", podIPWait)
	} else {
		h.log.Info("Pod got no address in time", "family", want, "waited", podIPWait)
	}
	return ""
}

// podIP is the Pod's address of the wanted family, "" when it has none.
// The podIPs list is read first, then the single podIP older kubelets
// write. An IPv4 address mapped into IPv6 is an inet4 address, advertised
// in its IPv4 form.
func podIP(p *corev1.Pod, want endpoint.Family) string {
	ips := make([]string, 0, len(p.Status.PodIPs)+1)
	for _, ip := range p.Status.PodIPs {
		ips = append(ips, ip.IP)
	}
	if len(ips) == 0 && p.Status.PodIP != "" {
		ips = append(ips, p.Status.PodIP)
	}
	for _, s := range ips {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if addr.Unmap().Is4() != (want == endpoint.Inet4) {
			continue
		}
		if addr.Is4In6() {
			return addr.Unmap().String()
		}
		return s
	}
	return ""
}
