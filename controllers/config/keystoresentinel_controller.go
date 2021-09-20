/*
Copyright 2021 Polyglot Systems.

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
	"bytes"
	"context"
	"k8s.io/apimachinery/pkg/api/errors"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1 "github.com/kenmoini/certificate-sentinel-operator/apis/config/v1"
	defaults "github.com/kenmoini/certificate-sentinel-operator/controllers/defaults"
	keystore "github.com/pavel-v-chernykh/keystore-go/v4"
	"strconv"
	"time"
)

//===========================================================================================
// SPOT TYPES
//===========================================================================================
// KeystoreSentinelReconciler reconciles a KeystoreSentinel object
type KeystoreSentinelReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//===========================================================================================
// INIT VARS
//===========================================================================================
// Implement reconcile.Reconciler so the controller can reconcile objects
var _ reconcile.Reconciler = &KeystoreSentinelReconciler{}
var LggrK = log.Log.WithName("keystore-sentinel-controller")
var SetLogLevelK int

//===========================================================================================
// INIT FUNC
//===========================================================================================
// init is fired when this controller is started
func init() {
	// Set logging
	log.SetLogger(zap.New())
}

//===========================================================================================
// RBAC GENERATORS
//===========================================================================================
//+kubebuilder:rbac:groups=config.polyglot.systems,resources=keystoresentinels,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=config.polyglot.systems,resources=keystoresentinels/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=config.polyglot.systems,resources=keystoresentinels/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch

//===========================================================================================
// RECONCILE
//===========================================================================================
// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the KeystoreSentinel object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *KeystoreSentinelReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	currentConfig, _ := config.GetConfig()
	clusterEndpoint := currentConfig.Host
	apiPath := currentConfig.APIPath
	//statusLists := configv1.KeystoreSentinelStatus{
	//	DiscoveredKeystores: []configv1.KeystoreInformation{},
	//}

	LogWithLevel("Connecting to:"+clusterEndpoint, 3, LggrK)
	LogWithLevel("API Path:"+apiPath, 3, LggrK)

	// Fetch the KeystoreSentinel instance
	keystoreSentinel := &configv1.KeystoreSentinel{}
	err := r.Get(ctx, req.NamespacedName, keystoreSentinel)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			LggrK.Error(err, "KeystoreSentinel resource not found on the cluster.")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		LggrK.Error(err, "Failed to get KeystoreSentinel")
		return ctrl.Result{}, err
	}

	// Log the used keystoreSentinel
	LogWithLevel("KeystoreSentinel loaded!  Found '"+keystoreSentinel.Name+"' in 'namespace/"+keystoreSentinel.Namespace+"'", 1, LggrK)
	SetLogLevelK = defaults.SetDefaultInt(defaults.LogLevel, keystoreSentinel.Spec.LogLevel)

	// Set default vars
	scanningInterval := defaults.SetDefaultInt(defaults.ScanningInterval, keystoreSentinel.Spec.ScanningInterval)
	targetName := keystoreSentinel.Spec.Target.TargetName

	serviceAccount := keystoreSentinel.Spec.Target.ServiceAccount
	targetKind := keystoreSentinel.Spec.Target.Kind
	//targetAPIVersion := keystoreSentinel.Spec.Target.APIVersion
	//targetDaysOut := keystoreSentinel.Spec.Target.DaysOut
	//timeOut := DaysOutToTimeOut(targetDaysOut)

	targetNamespaceLabels := keystoreSentinel.Spec.Target.NamespaceLabels
	targetLabels := keystoreSentinel.Spec.Target.TargetLabels
	targetLabelSelector, targetNamespaceLabelSelector := SetupLabelSelectors(targetLabels, targetNamespaceLabels, LggrK)

	//CertHashList := []string{}
	//expiredKeystoreCount := 0

	LogWithLevel("Processing KeystoreSentinel target: "+targetName, 2, LggrK)

	// Get ServiceAccount
	LogWithLevel("Using ServiceAccount: "+serviceAccount, 2, lggr)
	targetServiceAccount, _ := GetServiceAccount(serviceAccount, keystoreSentinel.Namespace, r.Client)
	var serviceAccountSecretName string
	targetServiceAccountSecret := &corev1.Secret{}

	// Find the right secret
	for _, em := range targetServiceAccount.Secrets {
		secret, _ := GetSecret(em.Name, keystoreSentinel.Namespace, r.Client)
		if secret.Type == "kubernetes.io/service-account-token" {
			// Get Secret
			serviceAccountSecretName = em.Name
			LogWithLevel("Using Secret: "+serviceAccountSecretName, 2, lggr)
			targetServiceAccountSecret, _ = GetSecret(serviceAccountSecretName, keystoreSentinel.Namespace, r.Client)
		}
	}

	// We didn't find a Secret to work against the API and thus can't create a new client
	if serviceAccountSecretName == "" {
		lggr.Error(err, "Failed to find API Token type Secret in ServiceAccount!")
		lggr.Info("Running reconciler again in " + strconv.Itoa(scanningInterval) + "s")
		time.Sleep(time.Second * time.Duration(scanningInterval))
		return ctrl.Result{}, err
	}

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
		lggr.Error(err, "Failed to create client")
		lggr.Info("Running reconciler again in " + strconv.Itoa(scanningInterval) + "s")
		time.Sleep(time.Second * time.Duration(scanningInterval))
		return ctrl.Result{}, err
	}

	effectiveNamespaces, _ := SetupNamespaceSlice(keystoreSentinel.Spec.Target.Namespaces, cl, lggr, serviceAccount, targetNamespaceLabelSelector, scanningInterval)

	// Loop through the namespaces in scope for this target
	for _, el := range effectiveNamespaces {
		targetListOptions := &client.ListOptions{Namespace: el, LabelSelector: targetLabelSelector}
		switch targetKind {
		//=========================== SECRETS
		case "Secret":
			// Get a list of Secrets in this Namespace
			secretList := &corev1.SecretList{}
			err = cl.List(context.Background(), secretList, targetListOptions)
			if err != nil {
				lggr.Error(err, "Failed to list secrets in namespace/"+el)
			}

			// Loop through Secrets
			for _, e := range secretList.Items {
				secretType := string(e.Type)
				if secretType == string(corev1.SecretTypeOpaque) || secretType == string(corev1.SecretTypeTLS) {
					LogWithLevel("Getting secret/"+e.Name+" in namespace/"+el+" (type="+secretType+")", 3, lggr)

					secretItem, _ := GetSecret(string(e.Name), el, cl)

					// Get the actual secret data
					for k, s := range secretItem.Data {
						// Store the secret as a base64 decoded string from the byte slice
						sDataStr := string(s)

						LogWithLevel(k+": "+sDataStr, 3, lggr)

						// See if this contains a binary object that holds a Java Keystore
						// See if this Keystore has a Certificate

					}
				}
			}
		//=========================== CONFIGMAPS
		case "ConfigMap":
			LogWithLevel("Checking for access to ConfigMap in ns/"+el, 3, lggr)
			// Get the list of ConfigMaps in this namespace
			configMapList := &corev1.ConfigMapList{}
			err = cl.List(context.Background(), configMapList, targetListOptions)
			if err != nil {
				lggr.Error(err, "Failed to list ConfigMaps in ns/"+el)
			}

			// Loop through ConfigMaps
			for _, e := range configMapList.Items {
				LogWithLevel("Getting configmap/"+e.Name+" in namespace/"+el, 3, lggr)
				configMapItem, _ := GetConfigMap(string(e.Name), el, cl)

				// Loop through the actual ConfigMap data
				for k, cm := range configMapItem.Data {
					// Store the secret as a base64 decoded string from the byte slice
					cmDataStr := string(cm)

					LogWithLevel(k+": "+cmDataStr, 3, lggr)

					// See if this contains a binary object that holds a Java Keystore
					// See if this Keystore has a Certificate
				}
			}
		//=========================== DEFAULT - INVALID KIND
		default:
			// Unsupported Object Kind
			lggr.Info("Invalid Target Kind!")
			lggr.Info("Running reconciler again in " + strconv.Itoa(scanningInterval) + "s")
			time.Sleep(time.Second * time.Duration(scanningInterval))
			return ctrl.Result{}, nil
		}
	}

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
func (r *KeystoreSentinelReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv1.KeystoreSentinel{}).
		Complete(r)
}

// ReadKeyStoreFromBytes takes in a byte slice and password and decodes the
func ReadKeyStoreFromBytes(byteData []byte, password []byte) (keystore.KeyStore, error) {
	f := bytes.NewReader(byteData)

	keyStore := keystore.New()
	if err := keyStore.Load(f, password); err != nil {
		return keyStore, err
	}

	return keyStore, nil
}
