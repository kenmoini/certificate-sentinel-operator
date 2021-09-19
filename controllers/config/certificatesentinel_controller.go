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
	"context"
	"crypto/sha1"
	"encoding/hex"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/rest"
	"reflect"
	"strconv"
	"strings"
	"time"

	//"k8s.io/api"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1 "github.com/kenmoini/certificate-sentinel-operator/apis/config/v1"
	defaults "github.com/kenmoini/certificate-sentinel-operator/controllers/defaults"
	helpers "github.com/kenmoini/certificate-sentinel-operator/controllers/helpers"
)

//===========================================================================================
// SPOT TYPES
//===========================================================================================
// CertificateSentinelReconciler reconciles a CertificateSentinel object
type CertificateSentinelReconciler struct {
	// client can be used to retrieve objects from the APIServer with the cached response.
	client.Client
	Scheme *runtime.Scheme
}

//===========================================================================================
// INIT VARS
//===========================================================================================
// Implement reconcile.Reconciler so the controller can reconcile objects
var _ reconcile.Reconciler = &CertificateSentinelReconciler{}
var lggr = log.Log.WithName("certificate-sentinel-controller")
var SetLogLevel int

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
//+kubebuilder:rbac:groups=config.polyglot.systems,resources=certificatesentinels,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=config.polyglot.systems,resources=certificatesentinels/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=config.polyglot.systems,resources=certificatesentinels/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch

//===========================================================================================
// RECONCILE
//===========================================================================================
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
	currentConfig, _ := config.GetConfig()
	clusterEndpoint := currentConfig.Host
	apiPath := currentConfig.APIPath
	statusLists := configv1.CertificateSentinelStatus{
		DiscoveredCertificates: []configv1.CertificateInformation{},
	}

	LogWithLevel("Connecting to:"+clusterEndpoint, 3, lggr)
	LogWithLevel("API Path:"+apiPath, 3, lggr)

	// Fetch the CertificateSentinel instance
	certificateSentinel := &configv1.CertificateSentinel{}
	err := r.Get(ctx, req.NamespacedName, certificateSentinel)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			lggr.Error(err, "CertificateSentinel resource not found on the cluster.")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		lggr.Error(err, "Failed to get CertificateSentinel")
		return ctrl.Result{}, err
	}

	// Log the used certificateSentinel
	LogWithLevel("CertificateSentinel loaded!  Found '"+certificateSentinel.Name+"' in 'namespace/"+certificateSentinel.Namespace+"'", 1, lggr)
	SetLogLevel = defaults.SetDefaultInt(defaults.LogLevel, certificateSentinel.Spec.LogLevel)

	// Set default vars
	scanningInterval := defaults.SetDefaultInt(defaults.ScanningInterval, certificateSentinel.Spec.ScanningInterval)
	targetName := certificateSentinel.Spec.Target.TargetName

	targetNamespaceLabels := certificateSentinel.Spec.Target.NamespaceLabels
	targetNamespaceLabelSelector := labels.NewSelector()

	serviceAccount := certificateSentinel.Spec.Target.ServiceAccount
	targetKind := certificateSentinel.Spec.Target.Kind
	targetAPIVersion := certificateSentinel.Spec.Target.APIVersion
	targetDaysOut := certificateSentinel.Spec.Target.DaysOut
	timeOut := daysOutToTimeOut(targetDaysOut)

	targetLabels := certificateSentinel.Spec.Target.TargetLabels
	targetLabelSelector := labels.NewSelector()

	effectiveNamespaces := []string{}
	CertHashList := []string{}
	expiredCertificateCount := 0

	LogWithLevel("Processing CertificateSentinel target: "+targetName, 2, lggr)

	// Create the label selectors for the target label filter
	if len(targetLabels) > 0 {
		// Loop through label filters
		for _, label := range targetLabels {
			activeFilter := returnFilterType(label.Filter)
			req, err := labels.NewRequirement(label.Key, activeFilter, label.Values)
			if err != nil {
				lggr.Error(err, "Failed to build labelSelector requirement for target!")
			}
			targetLabelSelector = targetLabelSelector.Add(*req)
		}
	}

	// Create the label selectors for the namespace label filter
	if len(targetNamespaceLabels) > 0 {
		// Loop through label filters
		for _, label := range targetNamespaceLabels {
			activeFilter := returnFilterType(label.Filter)
			req, err := labels.NewRequirement(label.Key, activeFilter, label.Values)
			if err != nil {
				lggr.Error(err, "Failed to build labelSelector requirement for namespace!")
			}
			targetNamespaceLabelSelector = targetNamespaceLabelSelector.Add(*req)
		}
	}

	// Get ServiceAccount
	LogWithLevel("Using ServiceAccount: "+serviceAccount, 2, lggr)
	targetServiceAccount, _ := GetServiceAccount(serviceAccount, certificateSentinel.Namespace, r.Client)
	var serviceAccountSecretName string
	targetServiceAccountSecret := &corev1.Secret{}

	// Find the right secret
	for _, em := range targetServiceAccount.Secrets {
		secret, _ := GetSecret(em.Name, certificateSentinel.Namespace, r.Client)
		if secret.Type == "kubernetes.io/service-account-token" {
			// Get Secret
			serviceAccountSecretName = em.Name
			LogWithLevel("Using Secret: "+serviceAccountSecretName, 2, lggr)
			targetServiceAccountSecret, _ = GetSecret(serviceAccountSecretName, certificateSentinel.Namespace, r.Client)
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

	// Loop through target namespaces
	for _, elem := range certificateSentinel.Spec.Target.Namespaces {
		namespaceList := &corev1.NamespaceList{}
		ns := strings.TrimSpace(elem)
		activeNamespace := ns
		activeNamespaceDisplayName := ns

		if ns == "*" {
			activeNamespace = ""
			activeNamespaceDisplayName = "*"
		}

		LogWithLevel("Querying for namespace/"+activeNamespaceDisplayName+" with sa/"+serviceAccount, 3, lggr)
		// Get Namespace with the cached context
		namespaceListOptions := &client.ListOptions{Namespace: activeNamespace, LabelSelector: targetNamespaceLabelSelector}
		err = cl.List(context.Background(), namespaceList, namespaceListOptions)
		if err != nil {
			lggr.Error(err, "Failed to list namespace in cluster!")
			lggr.Info("Running reconciler again in " + strconv.Itoa(scanningInterval) + "s")
			time.Sleep(time.Second * time.Duration(scanningInterval))
			return ctrl.Result{}, err
		}
		// Loop through NamespaceList, create the effectiveNamespaces slice
		for _, el := range namespaceList.Items {
			if !defaults.ContainsString(effectiveNamespaces, el.Name) {
				LogWithLevel("Adding ns/"+el.Name+" to scope", 3, lggr)
				effectiveNamespaces = append(effectiveNamespaces, el.Name)
			}
		}
	}

	// Loop through the namespaces in scope for this target
	for _, el := range effectiveNamespaces {
		switch targetKind {
		//=========================== SECRETS
		case "Secret":
			// Get a list of Secrets in this Namespace
			secretList := &corev1.SecretList{}
			err = cl.List(context.Background(), secretList, client.InNamespace(el))
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

						// See if this contains text about a Certificate
						if strings.Contains(sDataStr, "-----BEGIN CERTIFICATE-----") {
							LogWithLevel("CERTIFICATE FOUND! - ns/"+el+" - secret/"+string(e.Name)+" - key:"+k, 3, lggr)
							certs, _ := helpers.DecodeCertificateBytes(s, lggr)

							// Loop through the current collection of certificates
							for _, cert := range certs {
								// Check to see if this has already been added

								// Hash the Certificate and add it to the string slice
								h := sha1.New()
								//h.Write(cert.Raw)
								byteStream := []byte(targetKind + "-" + el + "-" + e.Name + "-" + cert.Subject.CommonName + "-" + cert.Issuer.CommonName)
								//h.Write(byteStream)
								h.Write(append(byteStream, cert.Raw...))
								sha_str := hex.EncodeToString(h.Sum(nil))

								if defaults.ContainsString(CertHashList, sha_str) {
									// Skipping Certificate
									LogWithLevel("Already found "+sha_str, 3, lggr)
								} else {
									// Add + Process
									LogWithLevel("Adding "+sha_str, 3, lggr)
									CertHashList = append(CertHashList, sha_str)

									discovered, _, messages := helpers.ParseCertificateIntoObjects(cert, timeOut, el, e.Name, k, targetKind, targetAPIVersion)
									// Loop through passed messages for log level 3
									for _, m := range messages {
										LogWithLevel(m, 3, lggr)
									}

									// Add decoded certificate to DiscoveredCertificates
									if len(discovered) != 0 {
										for _, iv := range discovered {
											if len(iv.TriggeredDaysOut) > 0 {
												expiredCertificateCount++
											}
											statusLists.DiscoveredCertificates = append(statusLists.DiscoveredCertificates, iv)
										}
									}
								}
							}

						}

					}
				}
			}
		//=========================== CONFIGMAPS
		case "ConfigMap":
			LogWithLevel("Checking for access to ConfigMap in ns/"+el, 3, lggr)
			// Get the list of ConfigMaps in this namespace
			configMapList := &corev1.ConfigMapList{}
			err = cl.List(context.Background(), configMapList, client.InNamespace(el))
			if err != nil {
				lggr.Error(err, "Failed to list ConfigMaps in ns/"+el)
			}

			// Loop through ConfigMaps
			for _, e := range configMapList.Items {
				LogWithLevel("Getting configmap/"+e.Name+" in namespace/"+el, 3, lggr)
				configMapItem, _ := GetConfigMap(string(e.Name), el, cl)

				// Loop through the actual ConfigMap data
				for k, cm := range configMapItem.Data {
					// See if this contains text about a Certificate
					if strings.Contains(string(cm), "-----BEGIN CERTIFICATE-----") {
						LogWithLevel("CERTIFICATE FOUND! - ns/"+el+" - configmap/"+string(e.Name)+" - key:"+k, 3, lggr)
						certs, _ := helpers.DecodeCertificateBytes([]byte(cm), lggr)

						// Loop through the current collection of certificates
						for _, cert := range certs {
							// Check to see if this has already been added

							// Hash the Certificate and add it to the string slice
							h := sha1.New()
							byteStream := []byte(targetKind + "-" + el + "-" + e.Name + "-" + cert.Subject.CommonName + "-" + cert.Issuer.CommonName)
							//h.Write(byteStream)
							h.Write(append(byteStream, cert.Raw...))
							sha_str := hex.EncodeToString(h.Sum(nil))

							if defaults.ContainsString(CertHashList, sha_str) {
								// Skipping Certificate
								LogWithLevel("Already found "+sha_str, 3, lggr)
							} else {
								// Add + Process
								LogWithLevel("Adding "+sha_str, 3, lggr)
								CertHashList = append(CertHashList, sha_str)

								discovered, _, messages := helpers.ParseCertificateIntoObjects(cert, timeOut, el, e.Name, k, targetKind, targetAPIVersion)
								// Loop through passed messages for log level 3
								for _, m := range messages {
									LogWithLevel(m, 3, lggr)
								}

								// Add decoded certificate to DiscoveredCertificates
								if len(discovered) != 0 {
									for _, iv := range discovered {
										if len(iv.TriggeredDaysOut) > 0 {
											expiredCertificateCount++
										}
										statusLists.DiscoveredCertificates = append(statusLists.DiscoveredCertificates, iv)
									}
								}
							}
						}

					}
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
	//}

	// Set updater check vars
	statusChanged := true
	oldDiscoveredCertificates := certificateSentinel.Status.DiscoveredCertificates
	oldLastReportSent := certificateSentinel.Status.LastReportSent
	oldExpiringCertificates := certificateSentinel.Status.ExpiringCertificates

	// Merge the Certificates into the .status of the CertificateSentinel object
	certificateSentinel.Status.DiscoveredCertificates = statusLists.DiscoveredCertificates
	certificateSentinel.Status.ExpiringCertificates = expiredCertificateCount

	// Process reports if needed, only if there are new certificates at risk
	if expiredCertificateCount > 0 {
		certificateSentinel.Status.LastReportSent = processReport(*certificateSentinel, lggr, r.Client)
	}

	// Check the difference in structs
	if reflect.DeepEqual(oldDiscoveredCertificates, certificateSentinel.Status.DiscoveredCertificates) && oldLastReportSent == certificateSentinel.Status.LastReportSent && oldExpiringCertificates == certificateSentinel.Status.ExpiringCertificates {
		statusChanged = false
	}

	if statusChanged {
		err = r.Status().Update(ctx, certificateSentinel)
		if err != nil {
			lggr.Error(err, "Failed to update CertificateSentinel status")
			return ctrl.Result{}, err
		}
	}
	LogWithLevel("Found "+strconv.Itoa(len(certificateSentinel.Status.DiscoveredCertificates))+" Certificates, "+strconv.Itoa(expiredCertificateCount)+" of which are at risk of expiring", 2, lggr)

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

//===========================================================================================
// SCOPED FUNCTIONS
//===========================================================================================

// returnFilterType just returns whatever string type simple name of label selection operations to that actual type
func returnFilterType(labelFilter string) selection.Operator {
	switch labelFilter {
	case "in":
		return selection.In
	case "notIn":
		return selection.NotIn
	case "equals":
		return selection.Equals
	case "doubleEquals":
		return selection.DoubleEquals
	case "notEquals":
		return selection.NotEquals
	case "greaterThan":
		return selection.GreaterThan
	case "lessThan":
		return selection.LessThan
	case "exists":
		return selection.Exists
	case "doesNotExist":
		return selection.DoesNotExist
	default:
		return selection.Equals
	}
}

// LogWithLevel implements simple log levels
func LogWithLevel(s string, level int, l logr.Logger) {
	if SetLogLevel >= level {
		l.Info(s)
	}
}

// daysOutToTimeOut converts an int slice of the number of days out to trigger an expiration alert on into a []configv1.TimeSlice time.Time array of computed date values to compare against certificate expiration dates with time.After
func daysOutToTimeOut(targetDaysOut []int) []configv1.TimeSlice {
	// Set Active DaysOut and time.Time formatted future dates
	daysOut := targetDaysOut
	if len(targetDaysOut) == 0 {
		daysOut = defaults.DaysOut
	}

	timeNow := metav1.Now()
	timeOut := []configv1.TimeSlice{}

	for _, tR := range daysOut {
		futureTime := time.Hour * 24 * time.Duration(tR)
		tSlice := configv1.TimeSlice{Time: metav1.NewTime(timeNow.Add(futureTime)), DaysOut: tR}
		timeOut = append(timeOut, tSlice)
	}
	return timeOut
}

// GetServiceAccount returns a single ServiceAccount by name in a given Namespace
func GetServiceAccount(serviceAccount string, namespace string, clnt client.Client) (*corev1.ServiceAccount, error) {
	targetServiceAccount := &corev1.ServiceAccount{}
	err := clnt.Get(context.Background(), client.ObjectKey{
		Namespace: namespace,
		Name:      serviceAccount,
	}, targetServiceAccount)

	if err != nil {
		lggr.Error(err, "Failed to get serviceaccount/"+serviceAccount+" in namespace/"+namespace)
		return targetServiceAccount, err
	}
	return targetServiceAccount, nil
}

// GetSecret returns a single Secret by name in a given Namespace
func GetSecret(name string, namespace string, clnt client.Client) (*corev1.Secret, error) {
	targetSecret := &corev1.Secret{}
	err := clnt.Get(context.Background(), client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}, targetSecret)

	if err != nil {
		lggr.Error(err, "Failed to get secret/"+name+" in namespace/"+namespace)
		return targetSecret, err
	}
	return targetSecret, nil
}

// GetConfigMap returns a single ConfigMap by name in a given Namespace
func GetConfigMap(name string, namespace string, clnt client.Client) (*corev1.ConfigMap, error) {
	targetConfigMap := &corev1.ConfigMap{}
	err := clnt.Get(context.Background(), client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}, targetConfigMap)

	if err != nil {
		lggr.Error(err, "Failed to get configmap/"+name+" in namespace/"+namespace)
		return targetConfigMap, err
	}
	return targetConfigMap, nil
}
