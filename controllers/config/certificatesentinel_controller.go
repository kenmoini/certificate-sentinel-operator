/*
Copyright 2021 Ken Moini.

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

package config

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"time"

	"context"
	"github.com/go-logr/logr"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	configv1 "github.com/kenmoini/certificate-sentinel-operator/apis/config/v1"
)

// CertificateSentinelReconciler reconciles a CertificateSentinel object
type CertificateSentinelReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=config.polyglot.systems,resources=certificatesentinels,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=config.polyglot.systems,resources=certificatesentinels/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=config.polyglot.systems,resources=certificatesentinels/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list
//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the CertificateSentinel object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *CertificateSentinelReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)
	log := r.Log.WithValues("certificateSentinel", req.NamespacedName)

	// Fetch the CertificateSentinel instance
	certificateSentinel := &cachev1alpha1.CertificateSentinel{}
	err := r.Get(ctx, req.NamespacedName, certificateSentinel)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			log.Info("CertificateSentinel resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to get CertificateSentinel")
		return ctrl.Result{}, err
	}

	// Log the use certificateSentinel
	log.Info("certificateSentinel loaded!")
	log.Info("Name: ", certificateSentinel.Name)
	log.Info("Namespace: ", certificateSentinel.Namespace)

	// your logic here

	// Reconcile successful - don't requeue
	// return ctrl.Result{}, nil
	// Reconcile failed due to error - requeue
	// return ctrl.Result{}, err
	// Requeue for any reason other than an error
	// return ctrl.Result{Requeue: true}, nil

	// Reconcile for any reason other than an error after 5 seconds
	return ctrl.Result{RequeueAfter: time.Second*5}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateSentinelReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv1.CertificateSentinel{}).
		Complete(r)
}
