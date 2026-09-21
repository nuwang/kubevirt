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
package istio_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/network/istio"
)

var _ = Describe("Istio mesh mode detection", func() {
	vmiWith := func(labels, annotations map[string]string) *v1.VirtualMachineInstance {
		return &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Labels: labels, Annotations: annotations}}
	}

	DescribeTable("AmbientMeshEnabled follows the istio.io/dataplane-mode VMI label",
		func(labels, annotations map[string]string, expected bool) {
			Expect(istio.AmbientMeshEnabled(vmiWith(labels, annotations))).To(Equal(expected))
		},
		Entry("label ambient", map[string]string{istio.DataplaneModeLabel: istio.DataplaneModeAmbient}, nil, true),
		Entry("label none", map[string]string{istio.DataplaneModeLabel: "none"}, nil, false),
		Entry("label absent", map[string]string{}, nil, false),
		Entry("nil labels", nil, nil, false),
		Entry("other value", map[string]string{istio.DataplaneModeLabel: "sidecar"}, nil, false),
		// istio-cni's label selector is an exact match; a differently cased value
		// would not enrol the pod, so it must not select the ambient NAT layout either.
		Entry("label with different case", map[string]string{istio.DataplaneModeLabel: "Ambient"}, nil, false),
		Entry("same key as an annotation only", nil, map[string]string{istio.DataplaneModeLabel: istio.DataplaneModeAmbient}, false),
	)

	DescribeTable("ProxyInjectionEnabled reads the sidecar annotation but yields to ambient",
		func(labels, annotations map[string]string, expected bool) {
			Expect(istio.ProxyInjectionEnabled(vmiWith(labels, annotations))).To(Equal(expected))
		},
		Entry("annotation true", nil, map[string]string{istio.InjectSidecarAnnotation: "true"}, true),
		Entry("annotation TRUE", nil, map[string]string{istio.InjectSidecarAnnotation: "TRUE"}, true),
		Entry("annotation false", nil, map[string]string{istio.InjectSidecarAnnotation: "false"}, false),
		Entry("annotation absent", nil, nil, false),
		Entry("annotation true but the VMI is labelled ambient",
			map[string]string{istio.DataplaneModeLabel: istio.DataplaneModeAmbient},
			map[string]string{istio.InjectSidecarAnnotation: "true"}, false),
	)
})
