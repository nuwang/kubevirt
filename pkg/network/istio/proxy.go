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

import (
	"strings"

	v1 "kubevirt.io/api/core/v1"
)

// ProxyInjectionEnabled reports whether the VMI requested an Istio sidecar
// via InjectSidecarAnnotation. A VMI labelled for the ambient mesh never gets
// a sidecar (ambient has no in-pod proxy), so ambient takes precedence.
func ProxyInjectionEnabled(vmi *v1.VirtualMachineInstance) bool {
	if AmbientMeshEnabled(vmi) {
		return false
	}
	if val, ok := vmi.GetAnnotations()[InjectSidecarAnnotation]; ok {
		return strings.EqualFold(val, "true")
	}
	return false
}

// AmbientMeshEnabled reports whether the VMI is labelled for the Istio ambient
// mesh (DataplaneModeLabel=DataplaneModeAmbient). The match is exact, like
// istio-cni's label selector: a value istio would not enroll must not select
// the ambient NAT layout either.
func AmbientMeshEnabled(vmi *v1.VirtualMachineInstance) bool {
	return vmi.GetLabels()[DataplaneModeLabel] == DataplaneModeAmbient
}

func GetLoopbackAddress() string {
	return "127.0.0.6"
}
