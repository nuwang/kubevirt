/*
 * This file is part of the KubeVirt project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright The KubeVirt Authors.
 *
 */

package masquerade

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/network/driver/nft"
	"kubevirt.io/kubevirt/pkg/network/driver/nmstate"
	"kubevirt.io/kubevirt/pkg/network/istio"
	"kubevirt.io/kubevirt/pkg/network/netmachinery"
	"kubevirt.io/kubevirt/pkg/util/net/ip"
)

type nftable interface {
	AddTable(family nft.IPFamily, name string) error
	AddChain(family nft.IPFamily, table, name string, chainspec ...string) error
	AddRule(family nft.IPFamily, table, chain string, rulespec ...string) error
}

type MasqPod struct {
	nftable                   nftable
	istioEnabled              bool
	ambientEnabled            bool
	portRangesSpecGateEnabled bool
}

const (
	natTable = "nat"

	preroutingChain          = "prerouting"
	postroutingChain         = "postrouting"
	inputChain               = "input"
	outputChain              = "output"
	kubevirtPreInboundChain  = "KUBEVIRT_PREINBOUND"
	kubevirtPostInboundChain = "KUBEVIRT_POSTINBOUND"

	// Ambient-mesh reply steering (see setupAmbientMarks). Filter-type base
	// chains at mangle priority, kept in the nat table so the whole masquerade
	// layout lives in one place.
	kubevirtAmbientPreroutingChain  = "KUBEVIRT_AMBIENT_PREROUTING"
	kubevirtAmbientPostroutingChain = "KUBEVIRT_AMBIENT_POSTROUTING"

	// istio-cni installs its nat PREROUTING chain (plaintext inbound REDIRECT
	// to ztunnel, ACCEPT for kubelet probes) at the standard dstnat priority.
	// Base chains registered at the same priority are evaluated newest-first,
	// and the masquerade layout is installed after the CNI ran, so in ambient
	// mode the KubeVirt chain moves one step later to let istio's run first:
	// its REDIRECT then wins the DNAT binding for plaintext inbound, while
	// probes and HBONE fall through to the catch-all below.
	natPreroutingPriority        = "-100"
	natPreroutingPriorityAmbient = "-99"
)

type option func(*MasqPod)

func New(opts ...option) MasqPod {
	m := MasqPod{nftable: nft.NFTBin{}}
	for _, opt := range opts {
		opt(&m)
	}
	return m
}

func WithIstio(enabled bool) option {
	return func(m *MasqPod) {
		m.istioEnabled = enabled
	}
}

// WithAmbient selects the Istio ambient-mesh masquerade layout. The launcher
// pod is enrolled in ambient by istio-cni (no in-pod proxy; the node's ztunnel
// listens on :15008/:15006/:15001 inside the pod netns), so the layout:
//   - keeps the catch-all DNAT to the guest (kubelet probes, non-mesh callers
//     that istio lets through),
//   - leaves the HBONE port (:15008) to ztunnel instead of NAT'ing it into the
//     guest, and lets istio's nat chain run first (see natPreroutingPriorityAmbient),
//   - DNATs ztunnel's dial to <pod-ip>:<port> into the guest, exactly as the
//     sidecar layout does for Envoy, and
//   - steers the guest's replies back to ztunnel (see setupAmbientMarks).
//
// Ambient takes precedence over Istio sidecar mode when both are set, since
// ambient has no in-pod proxy to terminate sidecar-mode traffic.
func WithAmbient(enabled bool) option {
	return func(m *MasqPod) {
		m.ambientEnabled = enabled
	}
}

func WithNftableAdapter(h nftable) option {
	return func(m *MasqPod) {
		m.nftable = h
	}
}

func WithPortRangesSpecGateEnabled(enabled bool) option {
	return func(m *MasqPod) {
		m.portRangesSpecGateEnabled = enabled
	}
}

func (m MasqPod) Setup(bridgeIfaceSpec, podIfaceSpec *nmstate.Interface, vmiIface v1.Interface) error {
	if bridgeIfaceSpec.IPv4.Enabled != nil && *bridgeIfaceSpec.IPv4.Enabled {
		if err := m.setupNATByFamily(nft.IPv4, podIfaceSpec, bridgeIfaceSpec, vmiIface); err != nil {
			return err
		}
	}
	if bridgeIfaceSpec.IPv6.Enabled != nil && *bridgeIfaceSpec.IPv6.Enabled {
		if err := m.setupNATByFamily(nft.IPv6, podIfaceSpec, bridgeIfaceSpec, vmiIface); err != nil {
			return err
		}
	}
	return nil
}

func (m MasqPod) setupNATByFamily(family nft.IPFamily, podIfaceSpec, bridgeIfaceSpec *nmstate.Interface, vmiIface v1.Interface) error {
	// Ambient takes precedence over sidecar: ambient has no in-pod proxy,
	// so the sidecar-mode layout (no catch-all DNAT, only SSH forwarded)
	// would leave kubelet probes and app traffic unable to reach the VM.
	istioSidecarMode := m.istioEnabled && !m.ambientEnabled

	if err := m.nftable.AddTable(family, natTable); err != nil {
		return err
	}
	preroutingPriority := natPreroutingPriority
	if m.ambientEnabled {
		preroutingPriority = natPreroutingPriorityAmbient
	}
	if err := m.nftable.AddChain(family, natTable, preroutingChain, fmt.Sprintf("{ type nat hook prerouting priority %s; }", preroutingPriority)); err != nil {
		return err
	}
	if err := m.nftable.AddChain(family, natTable, inputChain, "{ type nat hook input priority 100; }"); err != nil {
		return err
	}
	if err := m.nftable.AddChain(family, natTable, outputChain, "{ type nat hook output priority -100; }"); err != nil {
		return err
	}
	if err := m.nftable.AddChain(family, natTable, postroutingChain, "{ type nat hook postrouting priority 100; }"); err != nil {
		return err
	}
	if err := m.nftable.AddChain(family, natTable, kubevirtPreInboundChain); err != nil {
		return err
	}
	if err := m.nftable.AddChain(family, natTable, kubevirtPostInboundChain); err != nil {
		return err
	}
	if m.ambientEnabled {
		if err := m.nftable.AddChain(family, natTable, kubevirtAmbientPreroutingChain, "{ type filter hook prerouting priority -150; }"); err != nil {
			return err
		}
		if err := m.nftable.AddChain(family, natTable, kubevirtAmbientPostroutingChain, "{ type filter hook postrouting priority -150; }"); err != nil {
			return err
		}
	}

	guestIP := guestIPByGatewayInterface(family, *bridgeIfaceSpec)
	if err := m.nftable.AddRule(family, natTable, postroutingChain, string(family), "saddr", guestIP, "counter", "masquerade"); err != nil {
		return err
	}
	if err := m.nftable.AddRule(family, natTable, preroutingChain, "iifname", podIfaceSpec.Name, "counter", "jump", kubevirtPreInboundChain); err != nil {
		return err
	}
	if err := m.nftable.AddRule(family, natTable, postroutingChain, "oifname", bridgeIfaceSpec.Name, "counter", "jump", kubevirtPostInboundChain); err != nil {
		return err
	}

	if m.ambientEnabled {
		if err := m.setupAmbientMarks(family, bridgeIfaceSpec.Name); err != nil {
			return err
		}
		// Carve the HBONE port out before any forwarding rule (explicit ports
		// or the catch-all) so it is never NAT'd into the guest.
		if err := m.skipPreInboundDnatForPorts(family, istio.AmbientCarveOutPorts()...); err != nil {
			return err
		}
	}

	// Both Istio layouts dial the guest's ports at <pod-ip>:<port> from inside
	// the pod netns (Envoy from 127.0.0.6, ztunnel from the client's address),
	// so the pod address must be DNAT'd into the guest as loopback is.
	addressesToDnat := []string{ipLoopback(family)}
	if istioSidecarMode && family == nft.IPv4 {
		addressesToDnat = append(addressesToDnat, podIfaceSpec.IPv4.Address[0].IP)
	}
	if m.ambientEnabled {
		if podIP := podGlobalUnicastIP(family, *podIfaceSpec); podIP != "" {
			addressesToDnat = append(addressesToDnat, podIP)
		}
	}
	addressesToDnatSpec := fmt.Sprintf("{ %s }", strings.Join(addressesToDnat, ", "))

	for _, port := range vmiIface.Ports {
		if port.Protocol == "" {
			port.Protocol = "tcp"
		}
		protocol := strings.ToLower(port.Protocol)

		// The HBONE port belongs to ztunnel: emit no per-port rules for it
		// (the PREINBOUND carve-out above already keeps the SYN local).
		if m.ambientEnabled && protocol == "tcp" && isAmbientCarveOutPort(int(port.Port)) {
			continue
		}

		addressesToSnat := []string{ipLoopback(family)}

		if istioSidecarMode {
			var portsToForward []int
			for _, nonProxiedPort := range istio.NonProxiedPorts() {
				if int(port.Port) == nonProxiedPort {
					portsToForward = append(portsToForward, nonProxiedPort)
				}
			}
			if err := m.forwardPorts(family, guestIP, "tcp", portsToForward...); err != nil {
				return err
			}

			if family == nft.IPv4 {
				addressesToSnat = append(addressesToSnat, istio.GetLoopbackAddress())
			}
		} else {
			if err := m.forwardPorts(family, guestIP, protocol, int(port.Port)); err != nil {
				return err
			}
		}

		addressesToSnatSpec := fmt.Sprintf("{ %s }", strings.Join(addressesToSnat, ", "))
		gw := guestIPGateway(family, *bridgeIfaceSpec).String()
		if err := m.nftable.AddRule(family, natTable, kubevirtPostInboundChain, protocol, "dport", strconv.Itoa(int(port.Port)), string(family), "saddr", addressesToSnatSpec, "counter", "snat", "to", gw); err != nil {
			return err
		}

		if err := m.nftable.AddRule(family, natTable, outputChain, string(family), "daddr", addressesToDnatSpec, protocol, "dport", strconv.Itoa(int(port.Port)), "counter", "dnat", "to", guestIP); err != nil {
			return err
		}
	}

	portRanges := vmiIface.PortRanges
	if !m.portRangesSpecGateEnabled {
		portRanges = nil
	}

	for _, portRange := range portRanges {
		protocol := strings.ToLower(portRange.Protocol)
		addressesToSnat := []string{ipLoopback(family)}
		portRangeSpec := fmt.Sprintf("%d-%d", portRange.Start, portRange.End)

		if istioSidecarMode {
			var portsToForward []int
			for _, nonProxiedPort := range istio.NonProxiedPorts() {
				if int(portRange.Start) <= nonProxiedPort && nonProxiedPort <= int(portRange.End) {
					portsToForward = append(portsToForward, nonProxiedPort)
				}
			}
			if err := m.forwardPorts(family, guestIP, "tcp", portsToForward...); err != nil {
				return err
			}

			if family == nft.IPv4 {
				addressesToSnat = append(addressesToSnat, istio.GetLoopbackAddress())
			}
		} else {
			if err := m.forwardPortRange(family, guestIP, protocol, int(portRange.Start), int(portRange.End)); err != nil {
				return err
			}
		}

		addressesToSnatSpec := fmt.Sprintf("{ %s }", strings.Join(addressesToSnat, ", "))
		gw := guestIPGateway(family, *bridgeIfaceSpec).String()
		if err := m.nftable.AddRule(family, natTable, kubevirtPostInboundChain, protocol, "dport", portRangeSpec, string(family), "saddr", addressesToSnatSpec, "counter", "snat", "to", gw); err != nil {
			return err
		}

		if err := m.nftable.AddRule(family, natTable, outputChain, string(family), "daddr", addressesToDnatSpec, protocol, "dport", portRangeSpec, "counter", "dnat", "to", guestIP); err != nil {
			return err
		}
	}

	if len(vmiIface.Ports) == 0 && len(portRanges) == 0 {
		addressesToSnat := []string{ipLoopback(family)}
		switch {
		case istioSidecarMode:
			// Skip forwarding for the reserved istio ports
			if err := m.skipForwardPorts(family, istio.ReservedPorts()...); err != nil {
				return err
			}
			if err := m.forwardPorts(family, guestIP, "tcp", istio.NonProxiedPorts()...); err != nil {
				return err
			}
			if family == nft.IPv4 {
				addressesToSnat = append(addressesToSnat, istio.GetLoopbackAddress())
			}
		default:
			// Plain and ambient layouts: catch-all DNAT into the guest (in
			// ambient mode the HBONE carve-out precedes it in the chain).
			if err := m.nftable.AddRule(family, natTable, kubevirtPreInboundChain, "counter", "dnat", "to", guestIP); err != nil {
				return err
			}
		}
		addressesToSnatSpec := fmt.Sprintf("{ %s }", strings.Join(addressesToSnat, ", "))
		gw := guestIPGateway(family, *bridgeIfaceSpec).String()
		if err := m.nftable.AddRule(family, natTable, kubevirtPostInboundChain, string(family), "saddr", addressesToSnatSpec, "counter", "snat", "to", gw); err != nil {
			return err
		}
		if err := m.nftable.AddRule(family, natTable, outputChain, string(family), "daddr", addressesToDnatSpec, "counter", "dnat", "to", guestIP); err != nil {
			return err
		}
	}

	return nil
}

func (m MasqPod) skipForwardPorts(family nft.IPFamily, ports ...uint) error {
	loopback := ipLoopback(family)
	fmtPorts := formatPorts(ports)
	portsSpec := fmt.Sprintf("{ %s }", strings.Join(fmtPorts, ", "))
	if err := m.nftable.AddRule(family, natTable, outputChain, "tcp", "dport", portsSpec, string(family), "saddr", loopback, "counter", "return"); err != nil {
		return fmt.Errorf("failed to define skip forwarding for: %s/%s, err: %v", family, fmtPorts, err)
	}
	if err := m.nftable.AddRule(family, natTable, kubevirtPostInboundChain, "tcp", "dport", portsSpec, string(family), "saddr", loopback, "counter", "return"); err != nil {
		return fmt.Errorf("failed to define skip forwarding for: %s/%s, err: %v", family, fmtPorts, err)
	}
	return nil
}

// skipPreInboundDnatForPorts adds a `return` rule to KUBEVIRT_PREINBOUND for
// the given TCP destination ports, regardless of source. It must be added
// before any catch-all DNAT in the same chain so traffic on those ports
// skips the NAT and remains visible to whatever rule (e.g. istio-cni's
// inbound redirect) processes it next.
func (m MasqPod) skipPreInboundDnatForPorts(family nft.IPFamily, ports ...uint) error {
	if len(ports) == 0 {
		return nil
	}
	fmtPorts := formatPorts(ports)
	portsSpec := fmt.Sprintf("{ %s }", strings.Join(fmtPorts, ", "))
	if err := m.nftable.AddRule(family, natTable, kubevirtPreInboundChain, "tcp", "dport", portsSpec, "counter", "return"); err != nil {
		return fmt.Errorf("failed to define preinbound DNAT skip for: %s/%s, err: %v", family, fmtPorts, err)
	}
	return nil
}

// setupAmbientMarks gives ztunnel's connections into the guest a return path.
//
// ztunnel dials the workload from inside the pod netns with the *client's*
// source address (IP_TRANSPARENT). A regular pod answers from its own stack, so
// istio's mangle OUTPUT rule restores the connection mark and the reply is
// policy-routed (fwmark 0x111 -> table 100 -> local dev lo) to ztunnel's
// transparent socket. The guest's replies instead arrive on the bridge and go
// through PREROUTING, where istio restores nothing, so they would be routed out
// to the client and bypass ztunnel. KubeVirt therefore
//   - remembers ztunnel's own connections (packets carrying ztunnel's socket
//     mark, leaving towards the guest, original direction) by copying the mark
//     into the conntrack entry, and
//   - stamps istio's TPROXY mark onto the guest's replies before the routing
//     decision, so istio's policy route delivers them to ztunnel.
//
// The conntrack mark deliberately stays ztunnel's own (0x539), not 0x111:
// istio's OUTPUT restore rule only matches 0x111, and restoring that onto
// ztunnel's later forward packets would send them into table 100 as well.
func (m MasqPod) setupAmbientMarks(family nft.IPFamily, bridgeName string) error {
	ztunnelMark := istio.MarkMatchSpec(istio.ZtunnelPacketMark)

	saveRule := append([]string{"oifname", bridgeName, "ct", "direction", "original", "meta", "mark"}, ztunnelMark...)
	saveRule = append(saveRule, "counter", "ct", "mark", "set", istio.MarkSpec(istio.ZtunnelPacketMark))
	if err := m.nftable.AddRule(family, natTable, kubevirtAmbientPostroutingChain, saveRule...); err != nil {
		return fmt.Errorf("failed to define ambient conntrack marking on %s: %v", bridgeName, err)
	}

	restoreRule := append([]string{"iifname", bridgeName, "ct", "mark"}, ztunnelMark...)
	restoreRule = append(restoreRule, "counter", "meta", "mark", "set", istio.MarkSpec(istio.InpodTProxyMark))
	if err := m.nftable.AddRule(family, natTable, kubevirtAmbientPreroutingChain, restoreRule...); err != nil {
		return fmt.Errorf("failed to define ambient reply marking on %s: %v", bridgeName, err)
	}
	return nil
}

// podGlobalUnicastIP returns the pod interface's first global-unicast address
// of the family, or "" if it has none (IPv6 lists link-local first).
func podGlobalUnicastIP(family nft.IPFamily, podIface nmstate.Interface) string {
	addresses := podIface.IPv4.Address
	if family == nft.IPv6 {
		addresses = podIface.IPv6.Address
	}
	for _, addr := range addresses {
		if net.ParseIP(addr.IP).IsGlobalUnicast() {
			return addr.IP
		}
	}
	return ""
}

func isAmbientCarveOutPort(port int) bool {
	for _, p := range istio.AmbientCarveOutPorts() {
		if int(p) == port {
			return true
		}
	}
	return false
}

func formatPorts(ports []uint) []string {
	var formattedPorts []string
	for _, p := range ports {
		formattedPorts = append(formattedPorts, fmt.Sprintf("%d", p))
	}
	return formattedPorts
}

func (m MasqPod) forwardPorts(family nft.IPFamily, toIP string, protocol string, ports ...int) error {
	if len(ports) == 0 {
		return nil
	}
	p := strings.Trim(strings.Replace(fmt.Sprint(ports), " ", ", ", -1), "[]")
	portsSpec := fmt.Sprintf("{ %s }", p)
	return m.nftable.AddRule(family, natTable, kubevirtPreInboundChain, protocol, "dport", portsSpec, "counter", "dnat", "to", toIP)
}

func (m MasqPod) forwardPortRange(family nft.IPFamily, toIP string, protocol string, startPort, endPort int) error {
	portRangeSpec := fmt.Sprintf("%d-%d", startPort, endPort)
	return m.nftable.AddRule(family, natTable, kubevirtPreInboundChain, protocol, "dport", portRangeSpec, "counter", "dnat", "to", toIP)
}

func ipLoopback(family nft.IPFamily) string {
	if family == nft.IPv4 {
		return ip.IPv4Loopback
	}
	return net.IPv6loopback.String()
}

// guestIPByGatewayInterface calculates and returns the expected guest IP.
// The bridge IP is the guest default gateway and the next address is the one expected on the guest interface.
func guestIPByGatewayInterface(family nft.IPFamily, bridgeIface nmstate.Interface) string {
	ipAddr := guestIPGateway(family, bridgeIface)
	netmachinery.NextIP(ipAddr)
	return ipAddr.String()
}

func guestIPGateway(family nft.IPFamily, bridgeIface nmstate.Interface) net.IP {
	var ipAddr net.IP
	switch family {
	case nft.IPv4:
		ipAddr = net.ParseIP(bridgeIface.IPv4.Address[0].IP)
	case nft.IPv6:
		ipAddr = net.ParseIP(bridgeIface.IPv6.Address[0].IP)
	}
	return ipAddr
}
