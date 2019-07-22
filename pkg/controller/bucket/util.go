package bucket

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math/rand"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	bx "github.com/IBM-Cloud/bluemix-go"
	bxauth "github.com/IBM-Cloud/bluemix-go/authentication"
	bxendpoints "github.com/IBM-Cloud/bluemix-go/endpoints"
	bxrest "github.com/IBM-Cloud/bluemix-go/rest"
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

type KeyVal struct {
	Name  string
	Value string
}

// getIamToken : this function require the seed-secret-tokens secret to be available.
func (r *ReconcileBucket) getIamToken(secretnamespace string, apiKey *keyvalue.KeyValueSource, region *keyvalue.KeyValueSource) (string, error) {
	secretName := "seed-secret-tokens"

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
		if err != nil {
			return "", err
		} else if apiKeyVal == "" {
			if apiKey.SecretKeyRef != nil {
				return "", fmt.Errorf("No such key:%s defined in Secret:%s", apiKey.SecretKeyRef.Key, apiKey.SecretKeyRef.Name)
			}
			return "", fmt.Errorf("No such key:%s defined in ConfigMap:%s", apiKey.ConfigMapKeyRef.Key, apiKey.ConfigMapKeyRef.Name)
		}
		return ondemandAuthenticate(apiKeyVal, regionStr)
	} else {
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
func ondemandAuthenticate(apiKeyVal string, region string) (string, error) {

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
}

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

	var bindingKeyValues []KeyVal
	var serviceObj *ibmcloudoperator.Service
	// var apiKeyVal = ""
	var resourceInstanceIDVal = ""
	var endpointsVal = ""

	log.Info("processCredentials", "binding", bucket.Spec.BindingFrom, "apiKey", bucket.Spec.APIKey, "endpoints", bucket.Spec.Endpoints, "resource_instance_id", bucket.Spec.ResourceInstanceID)

	if !reflect.DeepEqual(bucket.Spec.BindingFrom, v1.BindingFrom{}) {
		log.Info("working on findind", "BindingObject", bucket.Spec.BindingFrom)
		bindingObject, err := r.getBindingObject(bucket.Spec.BindingFrom.Name, bucket.ObjectMeta.Namespace)
		if err != nil {
			log.Info("Unable to find", "BindingObject", bucket.Spec.BindingFrom.Name)
			if strings.Contains(bucket.Status.Message, "not found") && bucket.Status.State != resv1.ResourceStateWaiting {
				wlocker.QueueInstance(bucket, bucket.Spec.BindingFrom.Name)
				return bindingKeyValues, nil, false, err // Dont retry, the watcher will watch for the creation of BindingObject, set for PingInterval
			}
			return bindingKeyValues, nil, true, err // Binding Object is not ready yet, retry in retryInterval
		}
		wlocker.DeQueueInstance(bucket, bucket.Spec.BindingFrom.Name)
		secret, err := ibmcloudcomm.GetSecret(r, bindingObject)
		// log.Info("Location secret", "secret", secret.Data)
		// log.Info("Finding ", "Key", bucket.Spec.Credentials.BindingRef.Keys)
		serviceObj, _ = r.getServiceInstance(bindingObject)
		// apiKeyVal = string(secret.Data["apikey"])
		resourceInstanceIDVal = string(secret.Data["resource_instance_id"])

		endpointsVal = string(secret.Data["endpoints"])
	}

	//if !reflect.DeepEqual(bucket.Spec.APIKey, ibmcloudv1alpha1.ParametersFromSource{}) {
	/* if bucket.Spec.APIKey != nil {
		apiKeyVal, _ = r.getFromKeyReference(*bucket.Spec.APIKey, bucket.ObjectMeta.Namespace, apiKeyVal)
	}
	*/

	if bucket.Spec.ResourceInstanceID != nil {
		// if !reflect.DeepEqual(bucket.Spec.ResourceInstanceID, ibmcloudv1alpha1.ParametersFromSource{}) {
		resourceInstanceIDVal, _ = r.getFromKeyReference(*bucket.Spec.ResourceInstanceID, bucket.ObjectMeta.Namespace, resourceInstanceIDVal)
	}

	if bucket.Spec.Endpoints != nil {
		// if !reflect.DeepEqual(bucket.Spec.Endpoints, ibmcloudv1alpha1.ParametersFromSource{}) {
		endpointsVal, _ = r.getFromKeyReference(*bucket.Spec.Endpoints, bucket.ObjectMeta.Namespace, endpointsVal)
	}
	/* if apiKeyVal != "" {
		apiKey := KeyVal{
			Name:  "apikey",
			Value: apiKeyVal,
		}
		bindingKeyValues = append(bindingKeyValues, apiKey)
	}  */
	if strings.Contains(resourceInstanceIDVal, "::") {
		resourceInstanceIDVal = getGUID(resourceInstanceIDVal)
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
	log.Info("getFromKeyReference", "keyRef", keyRef)
	if keyRef.SecretKeyRef != nil {
		secretInstance := &corev1.Secret{}
		err := r.Get(context.Background(), types.NamespacedName{Name: keyRef.SecretKeyRef.Name, Namespace: namespace}, secretInstance)
		if err == nil {
			keyVal = string(secretInstance.Data[keyRef.SecretKeyRef.Key])
		} else {
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
func (r *ReconcileBucket) dyncGetEndpointUrl(bucket *ibmcloudv1alpha1.Bucket, endpoints string, token string) error {
	anno := bucket.GetObjectMeta().GetAnnotations()
	if anno != nil && anno["EndpointURL"] != "" {
		return nil
	}

	endpointsInfo := getEndpointInfo(bucket, endpoints, token)
	log.Info(bucket.GetObjectMeta().GetName(), "dyncGetEndpointUrl:endpointsInfo", endpointsInfo)

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
			} else {
				publics := infos["public"].(map[string]interface{})
				log.Info("", "Public", publics)
				str := fmt.Sprintf("%v", publics[location])
				return str, nil
			}
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

func (l *WaitQLock) QueueInstance(instance *ibmcloudv1alpha1.Bucket, secretName string) {
	l.Lock()
	defer l.Unlock()
	var repeat = false
	log.Info("QueueInstance", "namespace", instance.GetNamespace(), "name", instance.GetName(), "waitfor", secretName)

	for _, n := range l.waitBuckets {
		log.Info("==>", "namespace", instance.GetNamespace(), "name", instance.GetName(), "waitfor", secretName)

		if n.namespace == instance.GetNamespace() && n.name == instance.GetName() && n.waitfor == secretName {

			repeat = true
			log.Info("QueueInstance", "repeat", repeat)
		}
	}
	if !repeat {
		l.waitBuckets = append(l.waitBuckets, WaitItem{namespace: instance.GetNamespace(), name: instance.GetName(), waitfor: secretName})
	}
}

func (l *WaitQLock) DeQueueInstance(instance *ibmcloudv1alpha1.Bucket, secretName string) {
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

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func RandStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func RandString(length int) string {
	return RandStringWithCharset(length, charset)
}

func logRecorder(bucket *ibmcloudv1alpha1.Bucket, keysAndValues ...interface{}) {
	log.Info(bucket.ObjectMeta.Name, "info", keysAndValues)
}

func CheckCORS(bucket *ibmcloudv1alpha1.Bucket) bool {
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
func CheckRetentionPolicy(bucket *ibmcloudv1alpha1.Bucket) bool {
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
