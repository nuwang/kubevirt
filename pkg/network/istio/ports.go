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

package istio

import "fmt"

const (
	EnvoyAdminPort                     = 15000
	EnvoyOutboundPort                  = 15001
	EnvoyDebugPort                     = 15004
	EnvoyInboundPort                   = 15006
	EnvoyTunnelPort                    = 15008
	EnvoySecureNetworkPort             = 15009
	EnvoyMergedPrometheusTelemetryPort = 15020
	EnvoyHealthCheckPort               = 15021
	EnvoyDNSPort                       = 15053
	EnvoyPrometheusTelemetryPort       = 15090
	SSHPort                            = 22
)

func ReservedPorts() []uint {
	return []uint{
		EnvoyAdminPort,
		EnvoyOutboundPort,
		EnvoyDebugPort,
		EnvoyInboundPort,
		EnvoyTunnelPort,
		EnvoySecureNetworkPort,
		EnvoyMergedPrometheusTelemetryPort,
		EnvoyHealthCheckPort,
		EnvoyDNSPort,
		EnvoyPrometheusTelemetryPort,
	}
}

func NonProxiedPorts() []int {
	return []int{
		SSHPort,
	}
}

// AmbientCarveOutPorts are the ports that must NOT be NAT'd into the VM guest
// when the launcher pod is enrolled in Istio's ambient mesh, so that
// istio-cni's inbound redirect can hand the SYN to the local ztunnel.
//
// 15008 is the HBONE port that source-side ztunnels target for inbound mTLS
// traffic into mesh workloads. If KubeVirt's masquerade NATs it into the VM,
// the VM's TCP stack RSTs (no listener) and HBONE always fails.
func AmbientCarveOutPorts() []uint {
	return []uint{
		EnvoyTunnelPort,
	}
}

// Istio ambient in-pod packet marks (istio cni/pkg/iptables/iptables.go and
// ztunnel's PACKET_MARK). ztunnel sets ZtunnelPacketMark on every socket it
// opens inside the pod netns; istio-cni installs
// "ip rule fwmark InpodTProxyMark/InpodMarkMask lookup 100" with a local
// route so marked packets are delivered to ztunnel's transparent sockets.
const (
	ZtunnelPacketMark = 0x539
	InpodTProxyMark   = 0x111
	InpodMarkMask     = 0xfff
)

// MarkSpec renders a mark for an nft rule.
func MarkSpec(mark int) string {
	return fmt.Sprintf("0x%x", mark)
}

// MarkMatchSpec renders the masked comparison "& 0xfff == 0x..." for an nft
// "meta mark" / "ct mark" expression, as separate rule tokens.
func MarkMatchSpec(mark int) []string {
	return []string{"&", MarkSpec(InpodMarkMask), "==", MarkSpec(mark)}
}
