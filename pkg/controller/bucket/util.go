package bucket

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"time"

	ibmcloudoperator "github.com/ibm/cloud-operators/pkg/apis/ibmcloud/v1alpha1"
	ibmcloudcomm "github.com/ibm/cloud-operators/pkg/controller/binding"
	v1 "github.com/ibm/cloud-operators/pkg/lib/ibmcloud/v1"
	keyvalue "github.com/ibm/cloud-operators/pkg/lib/keyvalue/v1"
	resv1 "github.com/ibm/cloud-operators/pkg/lib/resource/v1"
	ibmcloudv1alpha1 "github.com/ibm/cos-bucket-operator/pkg/apis/ibmcloud/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ListBucketResult is used to realize Objects in a Bucket
type ListBucketResult struct {
	Name      string `xml:"Name"`
	Prefix    string `xml:"Prefix"`
	Marker    string `xml:"Marker"`
	MaxKeys   int    `xml:"MaxKeys"`
	Delimiter string `xml:"Delimiter"`
	Contents  []struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int    `xml:"Size"`
		Owner        struct {
			ID          string `xml:"ID"`
			DisplayName string `xml:"DisplayName"`
		} `xml:"Owner"`
		StorageClass string `xml:"StorageClass"`
	}
	IsTruncated bool `xml:"IsTruncated"`
}

// Delete is used to realize the tobe Deleted Object in a Bucket
type Delete struct {
	Object []Object `xml:"Object"`
}

// Object is used to keep key info
type Object struct {
	Key string `xml:"Key"`
}

//Endpoints is use to get the endpoint base on location and resilience
type Endpoints struct {
	IdentifyEndpoints struct {
		IAMToken  string `json:"iam_token"`
		IAMPolicy string `json:"iam_policy"`
	} `json:"identity-endpoints"`
	ServiceEndpoints struct {
		CrossRegion map[string]interface{} `json:"cross-region"`
		Regional    map[string]interface{} `json:"regional"`
		SingleSite  map[string]interface{} `json:"single_site"`
	} `json:"service-endpoints"`
}

// KeyVal is used to keep KeyVal of needed info
type KeyVal struct {
	Name  string
	Value string
}

func (r *ReconcileBucket) getIamTokenFromBinding(bucket *ibmcloudv1alpha1.Bucket) (string, error) {

	bindingObject, err := r.getBindingObject(bucket.Spec.BindingFrom.Name, bucket.ObjectMeta.Namespace)
	if err != nil {
		log.Info("Unable to find", "BindingObject", bucket.Spec.BindingFrom.Name, "error", err, "namespace", bucket.ObjectMeta.Namespace)
		if strings.Contains(bucket.Status.Message, "not found") && bucket.Status.State != resv1.ResourceStateWaiting {
			wlocker.queueInstance(bucket, bucket.Spec.BindingFrom.Name)
			return "", err // Dont retry, the watcher will watch for the creation of BindingObject, set for PingInterval
		}
		return "", err // Binding Object is not ready yet, retry in retryInterval
	}
	secret := &corev1.Secret{}
	secretName := bindingObject.Spec.SecretName
	if secretName == "" {
		secretName = bindingObject.ObjectMeta.Name
	}
	if err := r.Get(context.Background(), types.NamespacedName{Name: secretName, Namespace: bucket.ObjectMeta.Namespace}, secret); err != nil {
		if bucket.ObjectMeta.Namespace != "default" {
			if err := r.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: secretName}, secret); err != nil {
				return "", err
			}
		} else {
			return "", err
		}
	}
	regionStr := r.getRegionStr(bucket.ObjectMeta.Namespace, bucket.Spec.Region)

	if string(secret.Data["apikey"]) != "" {

		return ondemandAuthenticate(string(secret.Data["apikey"]), regionStr)
	}

	return "", fmt.Errorf("Program finding ApiKey")

}

// getRegion : get the region spec
func (r *ReconcileBucket) getRegionStr(secretnamespace string, region *keyvalue.KeyValueSource) string {
	regionStr := "us-south"
	if region != nil {
		_regionStr, err := r.getFromKeyReference(*region, secretnamespace, "us-south")
		if err != nil {
			return regionStr
		}
		regionStr = _regionStr
	}
	return regionStr
}

// getIamToken : this function require the seed-secret-tokens secret to be available.
func (r *ReconcileBucket) getIamToken(secretnamespace string, apiKey *keyvalue.KeyValueSource, region *keyvalue.KeyValueSource) (string, error) {
	secretName := "seed-secret-tokens"
	log.Info("getIamToken", "key", apiKey)
	// if !reflect.DeepEqual(apiKey, ibmcloudv1alpha1.ParametersFromSource{}) {
	if apiKey != nil {
		regionStr := "us-south"
		if region != nil {
			_regionStr, err := r.getFromKeyReference(*region, secretnamespace, "us-south")
			if err != nil {
				return "", err
			}
			regionStr = _regionStr
		}
		apiKeyVal, err := r.getFromKeyReference(*apiKey, secretnamespace, "")
		log.Info("getIamToken", "apiKeyVal", apiKeyVal, "error", err)
		if err != nil {
			return "", err
		} else if apiKeyVal == "" {
			if apiKey.SecretKeyRef != nil {
				return "", fmt.Errorf("No such key:%s defined in Secret:%s", apiKey.SecretKeyRef.Key, apiKey.SecretKeyRef.Name)
			} else if apiKey.ConfigMapKeyRef != nil {
				return "", fmt.Errorf("No such key:%s defined in ConfigMap:%s", apiKey.ConfigMapKeyRef.Key, apiKey.ConfigMapKeyRef.Name)
			}
			return "", fmt.Errorf("No SecretKeyRef or ConfigMapRef defined for apiKey")
		}
		return ondemandAuthenticate(apiKeyVal, regionStr)
	}
	secret := &corev1.Secret{}

	if err := r.Get(context.Background(), types.NamespacedName{Name: secretName, Namespace: secretnamespace}, secret); err != nil {
		if secretnamespace != "default" {
			if err := r.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: secretName}, secret); err != nil {
				return "", err
			}
		} else {
			return "", err
		}
	}

	if time.Now().Sub(secret.GetCreationTimestamp().Time).Minutes() > 5 {
		return r.ondemandGetToken(secretnamespace, apiKey)
	}
	return string(secret.Data["access_token"]), nil

}

func (r *ReconcileBucket) ondemandGetToken(secretnamespace string, apiKeyStruct *keyvalue.KeyValueSource) (string, error) {
	secretName := "seed-secret"
	apikeyRef := "api-key"
	apiKeyVal := ""
	secret := &corev1.Secret{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: secretName, Namespace: secretnamespace}, secret); err != nil {
		if secretnamespace != "default" {
			if err := r.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: secretName}, secret); err != nil {
				log.Info("ondemandGetToken", "error", err)
				return "", fmt.Errorf("Authenticating error: default Secret 'seed-secert' not found, please specity apiKey in Spec field")

			}
		} else {

			log.Info("ondemandGetToken", "error", err)
			return "", fmt.Errorf("Authenticating error: default Secret 'seed-secert' not found, please specify apiKey in Spec field")

		}
	}

	// if apiKeyVal == "" {
	region := "us-south"
	apikeyb, ok := secret.Data[apikeyRef]
	if !ok {
		log.Info("missing  key in secret", "Name", apikeyRef)

		return "", fmt.Errorf("missing [%s] key in secret/configmap defined in Spec 'apiKey'", apikeyRef)
	}
	apiKeyVal = string(apikeyb)
	regionb, ok := secret.Data["region"]
	if !ok {
		log.Info("set default region to us-south")
		regionb = []byte("us-south")
	}
	region = string(regionb)
	return ondemandAuthenticate(apiKeyVal, region)
}

/* func ondemandAuthenticate(apiKeyVal string, region string) (string, error) {

	config := bx.Config{
		EndpointLocator: bxendpoints.NewEndpointLocator(region),
	}

	auth, err := bxauth.NewIAMAuthRepository(&config, &bxrest.Client{HTTPClient: http.DefaultClient})
	if err != nil {
		// Invalid region. Do not requeue
		return "", fmt.Errorf("no endpoint found for region %s", region)
	}

	log.Info("authenticating...", "APIKey", apiKeyVal)
	if err := auth.AuthenticateAPIKey(apiKeyVal); err != nil {
		// TODO: check BX Error
		log.Info("Failed to Authenticating", "error", err)
		return "", fmt.Errorf("Failed to authenticate with APIKey from Spec")
	}
	return config.IAMAccessToken, nil
} */

func retrieveCredentials(credentials []KeyVal) (string, string, error) {

	resourceInstanceID := ""
	endpoints := ""

	for _, cred := range credentials {
		switch cred.Name {
		case "resource_instance_id":
			resourceInstanceID = cred.Value
		case "endpoints":
			endpoints = cred.Value

		}

	}

	if resourceInstanceID == "" && endpoints == "" {
		return resourceInstanceID, endpoints, fmt.Errorf("Missing credentials: ResourceInstanceID and Endpoints")
	} else if resourceInstanceID == "" {
		return resourceInstanceID, endpoints, fmt.Errorf("Missing credentials: ResourceInstanceID")
	} else if endpoints == "" {
		return resourceInstanceID, endpoints, fmt.Errorf("Missing credentials: Endpoints")
	}

	return resourceInstanceID, endpoints, nil
}
func (r *ReconcileBucket) processCredentials(bucket *ibmcloudv1alpha1.Bucket) ([]KeyVal, *ibmcloudoperator.Service, bool, error) {
	var err error
	var bindingKeyValues []KeyVal
	var serviceObj *ibmcloudoperator.Service
	var resourceInstanceIDVal = ""
	var endpointsVal = ""

	log.Info("processCredentials", "binding", bucket.Spec.BindingFrom, "apiKey", bucket.Spec.APIKey, "endpoints", bucket.Spec.Endpoints, "resource_instance_id", bucket.Spec.ResourceInstanceID)

	if !reflect.DeepEqual(bucket.Spec.BindingFrom, v1.BindingFrom{}) {
		log.Info("working on findind", "BindingObject", bucket.Spec.BindingFrom)
		bindingObject, err := r.getBindingObject(bucket.Spec.BindingFrom.Name, bucket.ObjectMeta.Namespace)
		if err != nil {
			log.Info("Unable to find", "BindingObject", bucket.Spec.BindingFrom.Name)
			if strings.Contains(bucket.Status.Message, "not found") && bucket.Status.State != resv1.ResourceStateWaiting {
				wlocker.queueInstance(bucket, bucket.Spec.BindingFrom.Name)
				return bindingKeyValues, nil, false, err // Dont retry, the watcher will watch for the creation of BindingObject, set for PingInterval
			}
			return bindingKeyValues, nil, true, err // Binding Object is not ready yet, retry in retryInterval
		}
		wlocker.deQueueInstance(bucket, bucket.Spec.BindingFrom.Name)
		secret, err := ibmcloudcomm.GetSecret(r, bindingObject)
		serviceObj, _ = r.getServiceInstance(bindingObject)
		resourceInstanceIDVal = string(secret.Data["resource_instance_id"])

		endpointsVal = string(secret.Data["endpoints"])
	}

	if bucket.Spec.ResourceInstanceID != nil {
		resourceInstanceIDVal, err = r.getFromKeyReference(*bucket.Spec.ResourceInstanceID, bucket.ObjectMeta.Namespace, resourceInstanceIDVal)
		if err != nil {
			return bindingKeyValues, nil, true, fmt.Errorf("ResourceInstanceID Spec missing")
		}
	}

	if bucket.Spec.Endpoints != nil {
		endpointsVal, err = r.getFromKeyReference(*bucket.Spec.Endpoints, bucket.ObjectMeta.Namespace, endpointsVal)
		if err != nil {
			return bindingKeyValues, nil, true, fmt.Errorf("Endpoints Spec missing")
		}
	}

	if strings.Contains(resourceInstanceIDVal, "::") {
		resourceInstanceIDVal = getGUID(resourceInstanceIDVal)
	}

	anno := bucket.GetObjectMeta().GetAnnotations()
	if anno["cred_ResourceInstanceID"] == "" || anno["cred_Endpoints"] == "" {
		anno["cred_ResourceInstanceID"] = resourceInstanceIDVal
		anno["cred_Endpoints"] = endpointsVal
		bucket.GetObjectMeta().SetAnnotations(anno)
		log.Info(bucket.ObjectMeta.Name, "Setup Annotation", anno)
		if err := r.Update(context.Background(), bucket); err != nil {
			return bindingKeyValues, nil, false, err
		}
	}
	if anno != nil && anno["cred_ResourceInstanceID"] != resourceInstanceIDVal {
		return bindingKeyValues, nil, true, fmt.Errorf("ResourceInstanceID changed: Original ID is %s, New ID is %s", anno["cred_ResourceInstanceID"], resourceInstanceIDVal)
	}
	if anno != nil && anno["cred_Endpoints"] != endpointsVal {
		return bindingKeyValues, nil, true, fmt.Errorf("Endpoints changed: Original Endpoints is %s, New Endpoints is %s", anno["cred_Endpoints"], endpointsVal)
	}

	if resourceInstanceIDVal != "" {
		resourceInstanceID := KeyVal{
			Name:  "resource_instance_id",
			Value: resourceInstanceIDVal,
		}
		bindingKeyValues = append(bindingKeyValues, resourceInstanceID)
	}
	if endpointsVal != "" {
		endpoints := KeyVal{
			Name:  "endpoints",
			Value: endpointsVal,
		}
		bindingKeyValues = append(bindingKeyValues, endpoints)
	}

	return bindingKeyValues, serviceObj, false, nil
}

func (r *ReconcileBucket) getFromKeyReference(keyRef keyvalue.KeyValueSource, namespace string, keyVal string) (string, error) {
	log.Info("getFromKeyReference", "keyRef", keyRef, "namespace", namespace)
	if keyRef.SecretKeyRef != nil {
		secretInstance := &corev1.Secret{}
		err := r.Get(context.Background(), types.NamespacedName{Name: keyRef.SecretKeyRef.Name, Namespace: namespace}, secretInstance)
		if err == nil {
			keyVal = string(secretInstance.Data[keyRef.SecretKeyRef.Key])
			return keyVal, nil
		} else {
			log.Info("getFromKeyReference", "error", err)
			return keyVal, err
		}
	} else if keyRef.ConfigMapKeyRef != nil {

		configmapInstance := &corev1.ConfigMap{}
		log.Info("working on findind", "ConfigMap", keyRef.ConfigMapKeyRef.Name)

		err := r.Get(context.Background(), types.NamespacedName{Name: keyRef.ConfigMapKeyRef.Name, Namespace: namespace}, configmapInstance)
		if err == nil {
			decodedStr, err := base64.StdEncoding.DecodeString(string(configmapInstance.Data[keyRef.ConfigMapKeyRef.Key]))
			if err != nil {
				keyVal = string(configmapInstance.Data[keyRef.ConfigMapKeyRef.Key])
			} else {
				keyVal = string(decodedStr)
			}

		} else {
			return keyVal, err
		}
	}

	return keyVal, nil
}

func (r *ReconcileBucket) getBindingObject(bindingObjectName string, bucketNameSpace string) (*ibmcloudoperator.Binding, error) {
	binding := &ibmcloudoperator.Binding{}
	gerr := r.Get(context.Background(), client.ObjectKey{
		Namespace: bucketNameSpace,
		Name:      bindingObjectName,
	}, binding)

	if gerr != nil {
		log.Info("", "error", gerr)
		return nil, gerr
	} else if binding.Status.State != resv1.ResourceStateOnline {
		return &ibmcloudoperator.Binding{}, fmt.Errorf("Binding Object %s not ready", bindingObjectName)
	}
	return binding, nil
}
func (r *ReconcileBucket) dyncGetEndpointURL(bucket *ibmcloudv1alpha1.Bucket, endpoints string, token string) error {
	anno := bucket.GetObjectMeta().GetAnnotations()
	if anno != nil && anno["EndpointURL"] != "" {
		return nil
	}

	endpointsInfo := getEndpointInfo(bucket, endpoints, token)
	log.Info(bucket.GetObjectMeta().GetName(), "dyncGetEndpointURL:endpointsInfo", endpointsInfo)

	var resiliency string
	var location string
	var buckettype string
	if anno != nil && anno["Resiliency"] != "" {
		resiliency = anno["Resiliency"]
		location = anno["Location"]
		buckettype = anno["BucketType"]
	} else {
		resiliency = bucket.Spec.Resiliency
		location = bucket.Spec.Location
		buckettype = bucket.Spec.BucketType
	}
	if buckettype == "" {
		buckettype = "public"
	}
	url := ""
	if resiliency == "cross-region" || resiliency == "Cross Region" {
		url, _ = dyncGetEndpoint(strings.ToLower(location), strings.ToLower(buckettype), endpointsInfo.ServiceEndpoints.CrossRegion)
	}
	if resiliency == "regional" {
		url, _ = dyncGetEndpoint(strings.ToLower(location), strings.ToLower(buckettype), endpointsInfo.ServiceEndpoints.Regional)

	}
	if resiliency == "single-site" {
		url, _ = dyncGetEndpoint(strings.ToLower(location), strings.ToLower(buckettype), endpointsInfo.ServiceEndpoints.SingleSite)

	}
	if url != "" {

		anno["EndpointURL"] = url
		bucket.GetObjectMeta().SetAnnotations(anno)
		if err := r.Update(context.Background(), bucket); err != nil {
			log.Info("Update Annotation", "error", err)
		}
		return nil
	}
	url, err := getEndpointURL(bucket)
	if err != nil {
		return fmt.Errorf("Unable to find URL")
	}

	anno["EndpointURL"] = url
	bucket.GetObjectMeta().SetAnnotations(anno)
	if err := r.Update(context.Background(), bucket); err != nil {
		log.Info("Update Annotation", "error", err)
	}
	return nil

}

func dyncGetEndpoint(location string, buckettype string, endpoints map[string]interface{}) (string, error) {
	log.Info("Working on ", "endpoints", endpoints, "location", location)
	for lo, ep := range endpoints {
		log.Info("CheckingLocation", "lo", lo, "Location", location, "bucketType", buckettype)
		if lo == location {
			infos := ep.(map[string]interface{})

			log.Info("dync", "infos", infos)
			if buckettype == "private" {
				publics := infos["private"].(map[string]interface{})
				str := fmt.Sprintf("%v", publics[location])
				return str, nil
			}
			publics := infos["public"].(map[string]interface{})
			log.Info("", "Public", publics)
			str := fmt.Sprintf("%v", publics[location])
			return str, nil

		}
	}
	return "", fmt.Errorf("Cannot find endpoints")

}
func getEndpointURL(bucket *ibmcloudv1alpha1.Bucket) (string, error) {
	anno := bucket.GetObjectMeta().GetAnnotations()
	if anno != nil && anno["EndpointURL"] != "" {
		return anno["EndpointURL"], nil
	}
	var resiliency string
	var location string
	var buckettype string
	if anno != nil && anno["Resiliency"] != "" {
		resiliency = anno["Resiliency"]
		location = anno["Location"]
		buckettype = anno["BucketType"]
	} else {
		resiliency = bucket.Spec.Resiliency
		location = bucket.Spec.Location
		buckettype = bucket.Spec.BucketType
	}
	if buckettype == "" {
		buckettype = "public"
	}
	urlPrefix := getURLPrefix(strings.ToLower(buckettype))
	locationstr := fmt.Sprintf("%s", location)
	if resiliency == "cross-region" || resiliency == "Cross Region" {
		url, err := getCrossRegionEndpoint(strings.ToLower(locationstr), urlPrefix)
		return url, err
	}
	if resiliency == "regional" {
		url, err := getRegionalEndpoint(strings.ToLower(locationstr), urlPrefix)
		return url, err
	}
	if resiliency == "single-site" {
		url, err := getSingleSiteEndpoint(strings.ToLower(locationstr), urlPrefix)
		return url, err
	}
	return "", nil

}

func getURLPrefix(buckettype string) string {
	var prefix string
	switch buckettype {
	case "private":
		prefix = "s3.private."
	default:
		prefix = "s3."
	}
	return prefix
}

func getRegionalEndpoint(locationtop string, urlPrefix string) (string, error) {
	// Need to get a dynamic way of getting endpoints
	return urlPrefix + locationtop + ".cloud-object-storage.appdomain.cloud", nil
}

func getCrossRegionEndpoint(locationtop string, urlPrefix string) (string, error) {
	// Need to get a dynamic way of getting endpoints

	switch locationtop {
	case "us", "us-geo":
		return urlPrefix + "us.cloud-object-storage.appdomain.cloud", nil

	case "eu", "eu-geo":
		return urlPrefix + "eu.cloud-object-storage.appdomain.cloud", nil

	case "ap", "ap-geo":

		return urlPrefix + "ap.cloud-object-storage.appdomain.cloud", nil

	default:
		return "", fmt.Errorf("Unrecognized region: %s", locationtop)
	}

}
func getSingleSiteEndpoint(locationtop string, urlPrefix string) (string, error) {
	// Need to get a dynamic way of getting endpoints
	return urlPrefix + locationtop + ".cloud-object-storage.appdomain.cloud", nil

}

// GetCloudEndpoint : Return endpoint URL based on region
func GetCloudEndpoint(region string) (string, error) {
	// TODO: use bx regions
	switch region {
	case "eu-de":
		return "api.eu-de.bluemix.net", nil
	case "au-syd":
		return "api.au-syd.bluemix.net", nil
	case "us-east":
		return "api.us-east.bluemix.net", nil
	case "us-south":
		return "api.ng.bluemix.net", nil
	case "eu-gb":
		return "api.eu-gb.bluemix.net", nil
	default:
		return "", fmt.Errorf("Unrecognized region: %s", region)
	}
}

func getStorageClassSpec(bucket *ibmcloudv1alpha1.Bucket) bytes.Buffer {
	loc := bucket.Spec.Location
	if strings.Contains(bucket.Spec.Location, "-geo") {
		_locs := strings.Split(bucket.Spec.Location, "-")
		loc = _locs[0]
	}
	var bucketConf CreateBucketConfiguration
	switch bucket.Spec.StorageClass {
	case "Standard":

		bucketConf.LocationConstraint = loc + "-standard"
	case "Vault":
		bucketConf.LocationConstraint = loc + "-vault"
	case "Cold Vault":
		bucketConf.LocationConstraint = loc + "-cold"
	case "Flex":
		bucketConf.LocationConstraint = loc + "-flex"
	}
	xmlBlob, _ := xml.Marshal(&bucketConf)
	log.Info("xmlBlob", "", bucketConf)
	out := *bytes.NewBuffer(xmlBlob)
	return out
}

func (l *WaitQLock) queueInstance(instance *ibmcloudv1alpha1.Bucket, secretName string) {
	l.Lock()
	defer l.Unlock()
	var repeat = false
	log.Info("queueInstance", "namespace", instance.GetNamespace(), "name", instance.GetName(), "waitfor", secretName)

	for _, n := range l.waitBuckets {
		log.Info("==>", "namespace", instance.GetNamespace(), "name", instance.GetName(), "waitfor", secretName)

		if n.namespace == instance.GetNamespace() && n.name == instance.GetName() && n.waitfor == secretName {

			repeat = true
			log.Info("queueInstance", "repeat", repeat)
		}
	}
	if !repeat {
		l.waitBuckets = append(l.waitBuckets, WaitItem{namespace: instance.GetNamespace(), name: instance.GetName(), waitfor: secretName})
	}
}

func (l *WaitQLock) deQueueInstance(instance *ibmcloudv1alpha1.Bucket, secretName string) {
	l.Lock()
	defer l.Unlock()
	filteredQueue := l.waitBuckets[:0]
	for _, n := range l.waitBuckets {
		if n.namespace != instance.GetNamespace() || n.name != instance.GetName() || n.waitfor != secretName {
			filteredQueue = append(filteredQueue, n)
		}
	}
	log.Info("DequeueInstance", "lenof", len(filteredQueue))
	l.waitBuckets = filteredQueue
}
func getGUID(instanceID string) string {
	instanceIDs := strings.Split(instanceID, ":")
	if len(instanceIDs) > 1 {
		return instanceIDs[len(instanceIDs)-3]

	}
	return instanceID

}

const charset = "abcdefghijklmnopqrstuvwxyz"

var seededRand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func randStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func randString(length int) string {
	return randStringWithCharset(length, charset)
}

func logRecorder(bucket *ibmcloudv1alpha1.Bucket, keysAndValues ...interface{}) {
	log.Info(bucket.ObjectMeta.Name, "info", keysAndValues)
}

func checkCORS(bucket *ibmcloudv1alpha1.Bucket) bool {
	annos := bucket.GetObjectMeta().GetAnnotations()
	oldCorsInfo := ibmcloudv1alpha1.CORSRule{}
	err := json.Unmarshal([]byte(annos["OrigCORSRule"]), &oldCorsInfo)
	log.Info("CheckCORS", "prev", oldCorsInfo, "new", bucket.Spec.CORSRules)
	if err == nil {
		if oldCorsInfo.AllowedHeader != bucket.Spec.CORSRules.AllowedHeader {
			log.Info("Header changed", "prev", oldCorsInfo.AllowedHeader, "now", bucket.Spec.CORSRules.AllowedHeader)
			return true
		}
		if oldCorsInfo.AllowedOrigin != bucket.Spec.CORSRules.AllowedOrigin {
			log.Info("Origin changed", "prev", oldCorsInfo.AllowedOrigin, "now", bucket.Spec.CORSRules.AllowedOrigin)
			return true
		}

		if !reflect.DeepEqual(oldCorsInfo.AllowedMethods, bucket.Spec.CORSRules.AllowedMethods) {
			log.Info("Method changed", "prev", oldCorsInfo.AllowedMethods, "now", bucket.Spec.CORSRules.AllowedMethods)
			return true
		}
	}

	return false
}

// CheckRetentionPolicy make sure the retention policy has changed
func checkRetentionPolicy(bucket *ibmcloudv1alpha1.Bucket) bool {
	annos := bucket.GetObjectMeta().GetAnnotations()
	oldRetentionPolicy := ibmcloudv1alpha1.RetentionPolicy{}
	err := json.Unmarshal([]byte(annos["OrigRetentionPolicy"]), &oldRetentionPolicy)
	if err == nil {

		if !reflect.DeepEqual(oldRetentionPolicy, bucket.Spec.RetentionPolicy) {
			log.Info("Retention Policy changed", "prev", oldRetentionPolicy, "now", bucket.Spec.RetentionPolicy)
			return true
		}
	}
	log.Info("RetionPolicy", "new", bucket.Spec.RetentionPolicy, "old", oldRetentionPolicy)
	return false
}

// InitImmutable init the immutable checking
func InitImmutable(bucket *ibmcloudv1alpha1.Bucket) map[string]string {
	anno := make(map[string]string)

	anno["Resiliency"] = bucket.Spec.Resiliency
	anno["Location"] = bucket.Spec.Location
	anno["BucketType"] = bucket.Spec.BucketType
	anno["StorageClass"] = bucket.Spec.StorageClass
	bindingFromStr, err := json.Marshal(bucket.Spec.BindingFrom)
	if err == nil {
		anno["BindingFrom"] = string(bindingFromStr)
	}

	APIKeyStr, err := json.Marshal(bucket.Spec.APIKey)
	if err == nil {
		anno["APIKey"] = string(APIKeyStr)
	}

	ResourceInstanceIDStr, err := json.Marshal(bucket.Spec.ResourceInstanceID)
	if err == nil {
		anno["ResourceInstanceID"] = string(ResourceInstanceIDStr)
	}

	EndpointsStr, err := json.Marshal(bucket.Spec.Endpoints)
	if err == nil {
		anno["Endpoints"] = string(EndpointsStr)
	}

	anno["Bindonly"] = strconv.FormatBool(bucket.Spec.BindOnly)
	log.Info(bucket.ObjectMeta.Name, "Inside InitImmutable", anno)
	return anno
}

func (r *ReconcileBucket) readyKeyProtect(keyProtectInfo *ibmcloudv1alpha1.KeyProtectInfo, namespace string, token string) (string, error) {
	_token, err := r.getIamToken(namespace, keyProtectInfo.APIKey, nil)
	if err != nil && _token != "" {
		token = _token
	}

	if keyProtectInfo.BindingFrom.Name != "" {
		bindingObject, err := r.getBindingObject(keyProtectInfo.BindingFrom.Name, namespace)
		if err != nil {
			log.Info("Unable to find", "BindingObject", keyProtectInfo.BindingFrom.Name, "Error", err)
			return "", err
		}
		serviceInstanceID := bindingObject.Status.InstanceID
		if strings.Contains(serviceInstanceID, "::") {
			serviceInstanceID = getGUID(serviceInstanceID)
		}
		return serviceInstanceID, nil
	} else if keyProtectInfo.InstanceID != "" {
		_, err := validInstance("", keyProtectInfo.InstanceID, token)
		if err == nil {
			return keyProtectInfo.InstanceID, nil
		}
		return "", fmt.Errorf("Invalid KeyProtect Instance Info, no such instance found %s", keyProtectInfo.InstanceID)
	} else if keyProtectInfo.InstanceName != "" {
		instanceID, err := validInstance(keyProtectInfo.InstanceName, "", token)
		if instanceID != "" && err == nil {
			return instanceID, nil
		}
		return "", fmt.Errorf("Invalid KeyProtect Instance Info, no such instance found %s", keyProtectInfo.InstanceName)
	}
	return "", fmt.Errorf("Missing KeyProtect Instance Info")
}
