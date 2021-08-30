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
	"context"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	//metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"strconv"
	"strings"
	"time"

	//"k8s.io/api"
	ctrl "sigs.k8s.io/controller-runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1 "github.com/kenmoini/certificate-sentinel-operator/apis/config/v1"
	defaults "github.com/kenmoini/certificate-sentinel-operator/controllers/defaults"
)

//========================================================================== SPOT TYPES
// CertificateSentinelReconciler reconciles a CertificateSentinel object
type CertificateSentinelReconciler struct {
	// client can be used to retrieve objects from the APIServer.
	client.Client
	Scheme *runtime.Scheme
}

// SecretLists
type SecretLists struct {
	Found   corev1.SecretList
	Expired corev1.SecretList
}

//========================================================================== INIT VARS
// Implement reconcile.Reconciler so the controller can reconcile objects
var _ reconcile.Reconciler = &CertificateSentinelReconciler{}

//========================================================================== INIT FUNC
func init() {
	// Set logging
	log.SetLogger(zap.New())

	//Set default variable values
}

//========================================================================== RBAC GENERATORS
//+kubebuilder:rbac:groups=config.polyglot.systems,resources=certificatesentinels,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=config.polyglot.systems,resources=certificatesentinels/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=config.polyglot.systems,resources=certificatesentinels/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch

//========================================================================== RECONCILE
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
	lggr := log.Log.WithName("cert-sentinel-controller")
	currentConfig, _ := config.GetConfig()
	clusterEndpoint := currentConfig.Host
	apiPath := currentConfig.APIPath
	lggr.Info("Connecting to:" + clusterEndpoint)
	lggr.Info("API Path:" + apiPath)

	// Fetch the CertificateSentinel instance
	certificateSentinel := &configv1.CertificateSentinel{}
	err := r.Get(ctx, req.NamespacedName, certificateSentinel)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			lggr.Info("CertificateSentinel resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		lggr.Error(err, "Failed to get CertificateSentinel")
		return ctrl.Result{}, err
	}

	// Log the used certificateSentinel
	lggr.Info("certificateSentinel loaded!  Found '" + certificateSentinel.Name + "' in 'ns/" + certificateSentinel.Namespace + "'")

	// Set default vars
	scanningInterval := defaults.SetDefaultInt(defaults.ScanningInterval, certificateSentinel.Spec.ScanningInterval)

	// Loop through Targets
	for _, element := range certificateSentinel.Spec.Targets {
		targetName := element.TargetName
		serviceAccount := element.ServiceAccount
		targetKind := element.Kind
		//targetAPIVersion := element.APIVersion
		lggr.Info("Processing CertificateSentinel target: " + targetName)

		// Get ServiceAccount
		lggr.Info("Using ServiceAccount: " + serviceAccount)
		targetServiceAccount := &corev1.ServiceAccount{}
		_ = r.Get(context.Background(), client.ObjectKey{
			Namespace: certificateSentinel.Namespace,
			Name:      serviceAccount,
		}, targetServiceAccount)
		serviceAccountSecretName := targetServiceAccount.Secrets[0].Name

		// Get Secret
		lggr.Info("Using Secret: " + serviceAccountSecretName)
		targetServiceAccountSecret := &corev1.Secret{}
		_ = r.Get(context.Background(), client.ObjectKey{
			Namespace: certificateSentinel.Namespace,
			Name:      serviceAccountSecretName,
		}, targetServiceAccountSecret)

		// Set up new client config
		newConfig := &rest.Config{
			BearerToken: string(targetServiceAccountSecret.Data[corev1.ServiceAccountTokenKey]),
			Host:        clusterEndpoint,
			APIPath:     apiPath,
			TLSClientConfig: rest.TLSClientConfig{
				CAData: targetServiceAccountSecret.Data[corev1.ServiceAccountRootCAKey],
			},
		}
		// Set up new Client
		cl, err := client.New(newConfig, client.Options{})
		if err != nil {
			fmt.Println("failed to create client")
			fmt.Printf("%+v\n", err)
			lggr.Info("Running reconciler again in " + strconv.Itoa(scanningInterval) + "s")
			time.Sleep(time.Second * time.Duration(scanningInterval))
			return ctrl.Result{}, err
		}

		// Loop through target namespaces
		for _, elem := range element.Namespaces {
			// This is a wildcard query to search all available namespaces
			ns := strings.TrimSpace(elem)
			if ns == "*" {
				lggr.Info("Querying for namespaces with sa/" + serviceAccount)
				// Query the API for all available namespaces this SA has access to
				// Get Namespaces with the cached context
				namespaceList := &corev1.NamespaceList{}
				err = cl.List(context.Background(), namespaceList, client.InNamespace(""))
				if err != nil {
					lggr.Info("Failed to list namespaces in cluster!")
					fmt.Printf("Failed to list namespaces in cluster: %v\n", err)
					lggr.Info("Running reconciler again in " + strconv.Itoa(scanningInterval) + "s")
					time.Sleep(time.Second * time.Duration(scanningInterval))
					return ctrl.Result{}, err
				}
				// Loop through Namespaces
				for _, el := range namespaceList.Items {
					// Check if the SA can query the types being targeted
					switch targetKind {
					case "Secret":
						lggr.Info("Checking for access to Secrets in ns/" + el.Name)

						/*
							listOptions := metav1.ListOptions{
								//FieldSelector:   "type=kubernetes.io/dockercfg",
								ResourceVersion: targetAPIVersion,
								Limit:           100,
							}
						*/

						secretList := &corev1.SecretList{}
						err = cl.List(context.Background(), secretList, client.InNamespace(el.Name))
						if err != nil {
							lggr.Info("Failed to list Secrets in ns/" + el.Name)
							fmt.Printf("Failed to list Secrets in ns/"+el.Name+": %v\n", err)
						}
						// Loop through Secrets
						for _, e := range secretList.Items {
							secretType := string(e.Type)
							if secretType == string(corev1.SecretTypeOpaque) || secretType == string(corev1.SecretTypeTLS) {
								lggr.Info("Getting " + string(e.Name) + ": " + secretType)

								// Get the actual secret data
							}
						}
					case "ConfigMap":
						lggr.Info("Checking for access to ConfigMap in ns/" + el.Name)
						configMapList := &corev1.ConfigMapList{}
						if err != nil {
							lggr.Info("Failed to list ConfigMaps in ns/" + el.Name)
							fmt.Printf("Failed to list ConfigMaps in ns/"+el.Name+": %v\n", err)
						}
						// Loop through ConfigMaps
						for _, e := range configMapList.Items {
							lggr.Info(e.Name)
						}
					default:
						// Unsupported Object Kind
						lggr.Info("Invalid Target Kind!")
						lggr.Info("Running reconciler again in " + strconv.Itoa(scanningInterval) + "s")
						time.Sleep(time.Second * time.Duration(scanningInterval))
						return ctrl.Result{}, nil
					}
				}
			}
		}

		// Set used namespaces - if wildcard, then query the API for namespaces the SA has access to
		// Loop through Namespaces, find target object
		// Switch between kinds for future availability of other data objects
		// If ConfigMap, loop through .data items
		// Decode each data item, test if has --- BEGIN CERTIFICATE --- in the first line
		// If Secret, loop through .data items
		// Decode each data item, test if has --- BEGIN CERTIFICATE --- in the first line
		// If a certificate is found, add to list of found certificates with decoded CA CN and Expiration
		// If the certificate is about to expire within a alerts[*].config.DaysOut interval then add it to the expired certs list
	}

	// your logic here

	// Reconcile successful - don't requeue
	// return ctrl.Result{}, nil
	// Reconcile failed due to error - requeue
	// return ctrl.Result{}, err
	// Requeue for any reason other than an error
	// return ctrl.Result{Requeue: true}, nil

	// Reconcile for any reason other than an error after 5 seconds
	lggr.Info("Running reconciler again in " + strconv.Itoa(scanningInterval) + "s")
	return ctrl.Result{RequeueAfter: time.Second * time.Duration(scanningInterval)}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateSentinelReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv1.CertificateSentinel{}).
		Complete(r)
}
