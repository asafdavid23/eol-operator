/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	helmv1alpha1 "github.com/asafd/eol-operator/api/v1alpha1"
)

var _ = Describe("HelmEOLAlert Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		const testNamespace = "default"

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: testNamespace,
		}

		newReconciler := func() *HelmEOLAlertReconciler {
			return &HelmEOLAlertReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				// Watcher, Enricher, and Notifiers left nil:
				//   - nil Enricher means reconcileEnriching skips AI enrichment
				//   - empty Notifiers means no external calls are made
			}
		}

		newAlert := func() *helmv1alpha1.HelmEOLAlert {
			return &helmv1alpha1.HelmEOLAlert{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: testNamespace,
				},
				Spec: helmv1alpha1.HelmEOLAlertSpec{
					ReleaseName:      resourceName,
					Namespace:        testNamespace,
					ChartName:        "cert-manager",
					InstalledVersion: "1.11.0",
					LatestVersion:    "1.16.3",
					VersionsBehind:   5,
					Severity:         "minor",
				},
			}
		}

		BeforeEach(func() {
			By("creating the custom resource for the Kind HelmEOLAlert")
			existing := &helmv1alpha1.HelmEOLAlert{}
			err := k8sClient.Get(ctx, typeNamespacedName, existing)
			if err != nil && errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, newAlert())).To(Succeed())
			}
		})

		AfterEach(func() {
			By("cleaning up the HelmEOLAlert resource")
			resource := &helmv1alpha1.HelmEOLAlert{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}
		})

		It("Pending phase: transitions to Enriching on first reconcile", func() {
			By("running the first reconcile")
			r := newReconciler()
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			By("checking the phase advanced to Enriching")
			updated := &helmv1alpha1.HelmEOLAlert{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal("Enriching"))
			Expect(updated.Status.AIReportGenerated).To(BeFalse())
			Expect(updated.Status.LastChecked).NotTo(BeNil())
		})

		It("Enriching phase: transitions to Notified with no enricher or notifiers", func() {
			By("advancing to Enriching via the first reconcile")
			r := newReconciler()
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			By("running the second reconcile (Enriching → Notified)")
			result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())
			// reconcileEnriching returns RequeueAfter 6h.
			Expect(result.RequeueAfter).To(Equal(6 * time.Hour))

			By("checking the phase advanced to Notified")
			updated := &helmv1alpha1.HelmEOLAlert{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal("Notified"))
			// No enricher configured — AIReportGenerated must stay false.
			Expect(updated.Status.AIReportGenerated).To(BeFalse())
			// No notifiers configured — list must be empty.
			Expect(updated.Status.NotificationsSent).To(BeEmpty())
		})

		It("Acknowledged phase: returns 24h requeue without error", func() {
			By("manually setting phase to Acknowledged")
			alert := &helmv1alpha1.HelmEOLAlert{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, alert)).To(Succeed())
			alert.Status.Phase = "Acknowledged"
			Expect(k8sClient.Status().Update(ctx, alert)).To(Succeed())

			By("reconciling the Acknowledged alert")
			r := newReconciler()
			result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(24 * time.Hour))
		})
	})
})
