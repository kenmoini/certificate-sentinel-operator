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

	"crypto/x509"
	"encoding/pem"

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

type timeSlices []timeSlice

type timeSlice struct {
	Time    time.Time
	DaysOut int
}

//========================================================================== INIT VARS
// Implement reconcile.Reconciler so the controller can reconcile objects
var _ reconcile.Reconciler = &CertificateSentinelReconciler{}
var lggr = log.Log.WithName("cert-sentinel-controller")

//========================================================================== INIT FUNC
func init() {
	// Set logging
	log.SetLogger(zap.New())
}

func decodeCertificateBytes(s []byte) ([]*x509.Certificate, error) {
	block, rest := pem.Decode(s)

	// Check to see if this can be decoded into a PEM block
	if block == nil || block.Type != "CERTIFICATE" {
		lggr.Info("Failed to decode PEM block containing a Certificate: " + string(rest))
	}

	// Parse the Certificate
	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil {
		lggr.Info("Failed to decode certificate!")
		fmt.Printf("Failed to decode certificate %v\n", err)
		return nil, err
	}
	return certs, nil
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
	currentConfig, _ := config.GetConfig()
	clusterEndpoint := currentConfig.Host
	apiPath := currentConfig.APIPath
	statusLists := configv1.CertificateSentinelStatus{
		DiscoveredCertificates: []configv1.CertificateInformation{},
		CertificatesAtRisk:     []configv1.CertificateInformation{},
	}

	//lggr.Info("Connecting to:" + clusterEndpoint)
	//lggr.Info("API Path:" + apiPath)

	// Fetch the CertificateSentinel instance
	certificateSentinel := &configv1.CertificateSentinel{}
	err := r.Get(ctx, req.NamespacedName, certificateSentinel)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			lggr.Info("CertificateSentinel resource not found on the cluster.")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		lggr.Error(err, "Failed to get CertificateSentinel")
		return ctrl.Result{}, err
	}

	// Log the used certificateSentinel
	lggr.Info("CertificateSentinel loaded!  Found '" + certificateSentinel.Name + "' in 'namespace/" + certificateSentinel.Namespace + "'")

	// Set default vars
	scanningInterval := defaults.SetDefaultInt(defaults.ScanningInterval, certificateSentinel.Spec.ScanningInterval)

	// Loop through Targets
	for _, element := range certificateSentinel.Spec.Targets {
		// Set Default Vars
		targetName := element.TargetName
		serviceAccount := element.ServiceAccount
		targetKind := element.Kind
		targetAPIVersion := element.APIVersion
		targetDaysOut := element.DaysOut
		effectiveNamespaces := []string{}

		// Set Active DaysOut and time.Time formatted future dates
		daysOut := targetDaysOut
		if len(targetDaysOut) == 0 {
			daysOut = defaults.DaysOut
		}
		timeNow := time.Now()
		timeOut := []timeSlice{}
		for _, r := range daysOut {
			tSlice := timeSlice{Time: timeNow.Add(time.Hour * 24 * time.Duration(r)), DaysOut: r}
			timeOut = append(timeOut, tSlice)
		}

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
			fmt.Println("fFailed to create client")
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
				// Loop through Namespaces, create the effectiveNamespaces slice
				for _, el := range namespaceList.Items {
					// Check if the SA can query the types being targeted
					effectiveNamespaces = append(effectiveNamespaces, el.Name)
				}
			} else {
				effectiveNamespaces = append(effectiveNamespaces, ns)
			}
			// Loop through the namespaces in scope for this target
			for _, el := range effectiveNamespaces {
				switch targetKind {
				//=========================== SECRETS
				case "Secret":
					// Get a list of Secrets
					secretList := &corev1.SecretList{}
					err = cl.List(context.Background(), secretList, client.InNamespace(el))
					if err != nil {
						lggr.Info("Failed to list secrets in namespace/" + el)
					}

					// Loop through Secrets
					for _, e := range secretList.Items {
						secretType := string(e.Type)
						if secretType == string(corev1.SecretTypeOpaque) || secretType == string(corev1.SecretTypeTLS) {
							lggr.Info("Getting secret/" + e.Name + " in namespace/" + el + " (type=" + secretType + ")")
							secretItem := &corev1.Secret{}
							err = cl.Get(context.Background(), client.ObjectKey{
								Namespace: el,
								Name:      string(e.Name),
							}, secretItem)

							if err != nil {
								lggr.Info("Failed to get secret/" + e.Name + " in namespace/" + el)
							}

							// Get the actual secret data
							for k, s := range secretItem.Data {
								// Store the secret as a base64 decoded string from the byte slice
								sDataStr := string(s)

								// See if this contains text about a Certificate
								if strings.Contains(sDataStr, "-----BEGIN CERTIFICATE-----") {
									lggr.Info("CERTIFICATE FOUND! " + k)
									certs, _ := decodeCertificateBytes(s)

									// Loop over parsed certificates
									for _, cert := range certs {
										expirationDate := cert.NotAfter
										// Create CertificateInformation object
										certInfo := configv1.CertificateInformation{Namespace: el, Name: e.Name, DataKey: k, Kind: targetKind, APIVersion: targetAPIVersion, Expiration: expirationDate.String(), CertificateAuthorityCommonName: cert.Issuer.CommonName, IsCertificateAuthority: cert.IsCA}

										// Add decoded certificate to DiscoveredCertificates
										statusLists.DiscoveredCertificates = append(statusLists.DiscoveredCertificates, certInfo)
										var addedToExpired bool

										for _, d := range timeOut {
											utcTime := d.Time.UTC()
											if utcTime.After(expirationDate) {
												lggr.Info("Certificate will expire in less than " + fmt.Sprint(d.DaysOut) + " days! Date: " + expirationDate.String())
												// Add to expired certs list
												if !addedToExpired {
													statusLists.CertificatesAtRisk = append(statusLists.CertificatesAtRisk, certInfo)
													addedToExpired = true
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
					lggr.Info("Checking for access to ConfigMap in ns/" + el)
					configMapList := &corev1.ConfigMapList{}
					if err != nil {
						lggr.Info("Failed to list ConfigMaps in ns/" + el)
						fmt.Printf("Failed to list ConfigMaps in ns/"+el+": %v\n", err)
					}
					// Loop through ConfigMaps
					for _, e := range configMapList.Items {
						lggr.Info("Getting configmap/" + e.Name + " in namespace/" + el)
						configMapItem := &corev1.ConfigMap{}
						err = cl.Get(context.Background(), client.ObjectKey{
							Namespace: el,
							Name:      string(e.Name),
						}, configMapItem)

						if err != nil {
							lggr.Info("Failed to get configmap/" + e.Name + " in namespace/" + el)
						}

						// Get the actual ConfigMap data
						for k, cm := range configMapItem.Data {
							// Store the secret as a base64 decoded string from the byte slice
							cmDataStr := string(cm)
							lggr.Info("Cm: " + cm)

							// See if this contains text about a Certificate
							if strings.Contains(cmDataStr, "-----BEGIN CERTIFICATE-----") {
								lggr.Info("CERTIFICATE FOUND! " + k)
								certs, _ := decodeCertificateBytes([]byte(cm))

								// Loop over parsed certificates
								for _, cert := range certs {
									expirationDate := cert.NotAfter
									// Create CertificateInformation object
									certInfo := configv1.CertificateInformation{Namespace: el, Name: e.Name, DataKey: k, Kind: targetKind, APIVersion: targetAPIVersion, Expiration: expirationDate.String(), CertificateAuthorityCommonName: cert.Issuer.CommonName, IsCertificateAuthority: cert.IsCA}

									// Add decoded certificate to DiscoveredCertificates
									statusLists.DiscoveredCertificates = append(statusLists.DiscoveredCertificates, certInfo)
									var addedToExpired bool
									for _, d := range timeOut {
										utcTime := d.Time.UTC()
										if utcTime.After(expirationDate) {
											lggr.Info("Certificate will expire in less than " + fmt.Sprint(d.DaysOut) + " days! Date: " + expirationDate.String())
											// Add to expired certs list
											if !addedToExpired {
												statusLists.CertificatesAtRisk = append(statusLists.CertificatesAtRisk, certInfo)
												addedToExpired = true
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
		}
	}

	// Merge the Certificates into the .status of the CertificateSentinel object
	certificateSentinel.Status = statusLists
	err = r.Status().Update(ctx, certificateSentinel)
	if err != nil {
		lggr.Error(err, "Failed to update CertificateSentinel status")
		return ctrl.Result{}, err
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
func (r *CertificateSentinelReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv1.CertificateSentinel{}).
		Complete(r)
}
