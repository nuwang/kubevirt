# Istio ambient mesh and the masquerade binding

## Summary

A VMI labelled `istio.io/dataplane-mode: ambient` runs its virt-launcher pod
inside Istio's ambient mesh: istio-cni enrolls the pod (the label is copied
onto it), and the masquerade binding lays out its NAT so that the node's
ztunnel can terminate mesh traffic for the guest and the guest's replies find
their way back. The VM then holds the launcher pod's SPIFFE identity for
`AuthorizationPolicy`/`PeerAuthentication`, and its own outbound TCP is
proxied by ztunnel with that identity.

```yaml
kind: VirtualMachineInstance
metadata:
  labels:
    istio.io/dataplane-mode: ambient
spec:
  domain:
    devices:
      interfaces:
        - name: default
          masquerade: {}
```

Ambient and sidecar modes are mutually exclusive. When the VMI also carries
`sidecar.istio.io/inject: "true"`, ambient wins and the launcher pod is
labelled `sidecar.istio.io/inject: "false"`.

## Why the plain and sidecar layouts do not work

Ambient has no in-pod proxy. The node's ztunnel opens listeners *inside* the
pod network namespace (HBONE on `:15008`, plaintext inbound on `:15006`,
outbound on `:15001`) and istio-cni installs iptables rules there:

- nat `PREROUTING`: plaintext inbound TCP (anything but `:15008`) is
  `REDIRECT`ed to `:15006`; kubelet probes (source `169.254.7.127`) are
  accepted; TCP arriving on a `istio.io/reroute-virtual-interfaces` interface
  (KubeVirt sets `k6t-eth0`) is `REDIRECT`ed to `:15001`, so guest-originated
  traffic becomes mesh outbound.
- mangle `PREROUTING`/`OUTPUT`: ztunnel's own sockets carry mark `0x539`;
  connections it opens to the workload over `lo` get connmark `0x111`, which
  is restored onto the workload's locally generated replies. A policy route
  (`fwmark 0x111 → table 100 → local dev lo`) delivers those replies to
  ztunnel's `IP_TRANSPARENT` socket, because ztunnel dials the workload with
  the *client's* source address.

The plain masquerade layout DNATs every TCP port on `eth0` into the guest,
including `:15008`: the peer ztunnel's HBONE SYN lands in a guest with no
listener and is reset. The sidecar layout removes the catch-all and forwards
only `:22`, expecting an Envoy in the pod: with no proxy, kubelet probes and
application traffic reach nothing.

## The ambient layout

Rendered for guest `10.0.2.2`, gateway `10.0.2.1`, pod address `10.222.222.1`,
no explicit `ports`:

```
table ip nat {
  chain prerouting  { type nat hook prerouting priority -99; }
  chain input       { type nat hook input priority 100; }
  chain output      { type nat hook output priority -100; }
  chain postrouting { type nat hook postrouting priority 100; }
  chain KUBEVIRT_AMBIENT_PREROUTING  { type filter hook prerouting priority -150; }
  chain KUBEVIRT_AMBIENT_POSTROUTING { type filter hook postrouting priority -150; }

  postrouting:                  ip saddr 10.0.2.2 counter masquerade
  prerouting:                   iifname eth0 counter jump KUBEVIRT_PREINBOUND
  postrouting:                  oifname k6t-eth0 counter jump KUBEVIRT_POSTINBOUND
  KUBEVIRT_AMBIENT_POSTROUTING: oifname k6t-eth0 ct direction original meta mark & 0xfff == 0x539 counter ct mark set 0x539
  KUBEVIRT_AMBIENT_PREROUTING:  iifname k6t-eth0 ct mark & 0xfff == 0x539 counter meta mark set 0x111
  KUBEVIRT_PREINBOUND:          tcp dport { 15008 } counter return
  KUBEVIRT_PREINBOUND:          counter dnat to 10.0.2.2
  KUBEVIRT_POSTINBOUND:         ip saddr { 127.0.0.1 } counter snat to 10.0.2.1
  output:                       ip daddr { 127.0.0.1, 10.222.222.1 } counter dnat to 10.0.2.2
}
```

Each difference from the plain layout, and why:

- **`prerouting` at priority `-99`.** istio-cni's nat `PREROUTING` chain sits
  at the standard dstnat priority (`-100`). Base chains registered at the same
  priority are evaluated newest-first, and the masquerade layout is installed
  after the CNI ran, so at `-100` the KubeVirt catch-all DNAT would win the NAT
  binding for a plaintext connection and it would bypass ztunnel — and with it
  any `AuthorizationPolicy`. At `-99` istio's chain runs first: its `REDIRECT`
  to `:15006` wins for plaintext inbound, while kubelet probes (`ACCEPT`) and
  HBONE (not touched by istio) fall through to the KubeVirt chain.
- **`tcp dport { 15008 } return` before any DNAT.** The HBONE port stays local
  so ztunnel's in-pod listener receives it. The rule precedes explicit-port and
  catch-all forwarding alike; an explicit TCP port 15008 in `ports` emits no
  rules of its own (a UDP port 15008 is unrelated and forwarded normally).
- **Pod address in the `output` DNAT set.** After terminating HBONE (or
  accepting plaintext on `:15006`), ztunnel dials `<pod-ip>:<port>` from inside
  the netns. Without the DNAT that connection is delivered to the launcher's
  own stack and refused. The sidecar layout already does this for Envoy. For
  IPv6 the pod's first global-unicast address is used.
- **Connection marking on the bridge.** The guest's replies arrive on
  `k6t-eth0` and traverse `PREROUTING`, where istio restores no mark, so they
  would be routed straight out to the client instead of to ztunnel's
  transparent socket. `KUBEVIRT_AMBIENT_POSTROUTING` remembers ztunnel's
  connections into the guest by copying its socket mark into the conntrack
  entry (original direction only, so ztunnel's replies on guest-originated
  connections are not tagged); `KUBEVIRT_AMBIENT_PREROUTING` stamps istio's
  `0x111` onto the guest's replies before the routing decision, and istio's
  policy route delivers them to ztunnel. The conntrack mark is `0x539`, not
  `0x111`: istio's mangle `OUTPUT` restore rule matches `0x111` only, and
  restoring that onto ztunnel's own later forward packets would send them into
  table 100 as well.

Nothing else changes: the catch-all DNAT keeps kubelet probes and any traffic
istio lets through reaching the guest exactly as in plain mode, and the
loopback SNAT/DNAT pair is untouched.

## Limitations

- Only the VMI label selects the layout. A namespace-level
  `istio.io/dataplane-mode: ambient` label enrolls the launcher pod through
  istio-cni but KubeVirt does not see it; such a pod gets the plain layout and
  is unreachable through the mesh. Either label the VMI, or exclude
  `kubevirt.io=virt-launcher` pods from the CNI's `enablementSelectors` unless
  they carry the label.
- Guest UDP is never meshed: istio's virtual-interface redirect is TCP-only
  and its DNS capture applies to `OUTPUT` only.
- The layout couples to istio's in-pod constants (ports `15008`/`15006`/
  `15001`, marks `0x539`/`0x111`/`0xfff`), like the sidecar layout couples to
  Envoy's ports. They are collected in `pkg/network/istio`.
- Masquerade only; the passt binding would need ztunnel's ports excluded from
  its own port binding instead.
