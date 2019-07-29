# Bucket Operator 
apiVersion: ibmcloud.ibm.com/v1alpha1

kind: Bucket

### 1. Introduction

<em>Bucket operator is used to control life-cycle of Cloud Object Storage Bucket </em>


* Bucket name will be the name of the CR plus a ramdom character string (8 chars long). For example, if your CR name is my-cos-bucket-1, your bucket name will be my-cos-bucket-1-xxxxxxxx, where xxxxxxxx is a random 8 characters string. BucketName can be retrieved by checking the CR's metadata->annotations["BucketName"]

    For example: using kubectl get bucket.ibmcloud.ibm.com my-cos-bucket-1 -o yaml
    ```
    apiVersion: ibmcloud.ibm.com/v1alpha1
    kind: Bucket
    metadata:
      name: my-cos-bucket-1
      annotations:
        BucketName: my-cos-bucket-1-xsdqefps
      ...
    ```

* Bucket operator can be used independent of the [IBM Cloud Operators](https://github.com/ibm/cloud-operators). 
  * Using Binding object: Please reference to the [IBM Cloud Operators](https://github.com/ibm/cloud-operators) for installation detail and please see the [sample service and binding yaml](#sampleYaml).
  * To use bucket operator independently, user needs to provide the following information thru kubernetes secrets or configmap. (see [section 2](#section2) for schema information). The `apikey` field in the IBM Cloud Object Storage's service credentail can be used instead of IBM Cloud API Key. 
    1. apiKey

          Specification:


            apiKey:
              secretKeyRef:
                name: <name of the kubernetes secret>
                key: <the name of the key inside secret identified by name>
              configMapKeyRef:
                name: <name of the configmap>
                key: <the name of the key inside configmap identified by name>


        +  option 1. use the installation script 
               ```
               curl -sL https://raw.githubusercontent.com/IBM/cos-bucket-operator/master/hack/install-bucket-operator.sh | bash 
               ```

        + option 2. create a new IBMCloud API Key 

              Use ibmcloud cli to create a new IBM Cloud API Key - `ibmcloud iam api-key-create <APIKeyName>`

              Please see [Understanding IBM Cloud API Key](https://cloud.ibm.com/docs/iam?topic=iam-manapikey)
              Refer to [Example Script](#ibmcloudapikey) for how to create ibmcloud api key and use it to create kubernetes secret

        + option 3. use an existing IBM Cloud API Key - create either a kubernetes secret or configmap. 
            And then use the following spec to specify where to locate the apiKey
            
    2. endpoints - from the Cloud Object Storage credentials. Please see [Section 3](#section3)

    3. resourceInstanceID - from the Cloud Object Storage Credentials.

* If the bucket was removed outside of the Lifecycle of the controller, the bucket will be created with name plus different random strings at the end
* Object inside Bucket will be removed when the deleting the controller, KeepIfNotEmpty flag can be used to avoid accidentally removing of non-empty bucket. With this flag, the Deleting action will fail and will stay in "Deleting" status, until user manual remove the object(s) inside the bucket. Or remove the KeepIfNotEmpty flag from the yaml spec and use `kubectl apply` to change the desired action.
* The location, resiliency cannot be changed without removing and recreating the bucket.
* The CORS rules and RetentionPolicy can be changed by using "kubectl apply"
* `bindOnly` is used to bind to existing bucket. You can also use this to change the cors rule and retention policy of existing bucket. Removing the binconly CR will not remove the bucket, but the original CORS rule and Policy will be restored. `Note: Once you create a retention policy it can not be deleted.` To understand the `Retention Policy`, please reference [Immutable Object Storage](https://cloud.ibm.com/docs/services/cloud-object-storage/basics?topic=cloud-object-storage-immutable)  
* Support for KeyProtect - Key Protect allows you to manage your own keys to encrypt objects in a bucket. Please see [KeyProtect setup](#keyprotectSetup) section for detail. The Key ID can be found by using ```kubectl get bucket.ibmcloud.ibm.com <CR name> -o yaml``` and look under metadata->annotation->```KeyProtectKeyID```
The spec "apiKey" under KeyProtect should be pointing to the kubernets secret or kubernets configmap for ibm cloud api Key. Since apikey in IBM Cloud Object Storage's service credential is limited for Bucket operation, it cannot be used for KeyProtect service.

### <a name="section2"></a>2. Bucket Controller Schema

The Credentials field inside Spec should contains three needed information about where to retrieve the values of `resource_instance_id`, `apikey`, and `endpoints`.
If no keys is defined in the spec of either bindingRef, secretKeyRef or configMapKeyRef, then the operators will try to find all 3 values from it.
If there are duplicate key specified for more than one Ref, the latter one will overwrite the value in the previous one. The sequence is configMapRef > secretKeyRef > bindingRef. 
```
apiVersion: ibmcloud.ibm.com/v1beta1
kind: Bucket
metadata:
  name: <name of the CR>
spec:
  bindingFrom:
    name: <name of the binding CR>
  apiKey:
    secretKeyRef:
      name: <name of the kubernetes secret>
      key: <the name of the key inside secret identified by name>
    configMapKeyRef:
      name: <name of the configmap>
      key: <the name of the key inside configmap identified by name>
  endpoints:
    secretKeyRef:
      name: <name of the kubernetes secret>
      key: <the name of the key inside secret identified by name>
    configMapKeyRef:
      name: <name of the configmap>
      key: <the name of the key inside configmap identified by name>
  resourceInstanceID:
    secretKeyRef:
      name: <name of the kubernetes secret>
      key: <the name of the key inside secret identified by name>
    configMapKeyRef:
      name: <name of the configmap>
      key: <the name of the key inside configmap identified by name>
  resiliency: <Possible value: Cross Region, Regional, Single Site>
  location: <Possible value: depend on the resuleicy, please see attached table>
  storageClass: <Possible value: Standard, Value, Cold Value, Flex>
  keyProtect:
    bindingFrom:
      name: <BindingObject name of the KeyProtect Instance, this option requires using ibmcloud-operator>
    instanceName: <Key Protect Instance Name>
    instanceID: <Key Protect Instance ID>
    keyName: <Name of the KeyProtect Key>
    APIKey:  
      secretKeyRef:
        name: <name of the kubernetes secret>
        key: <the name of the key inside secret identified by name>
      configMapKeyRef:
        name: <name of the configmap>
  bindOnly: <true, false(default): bind to existing bucket>
  corsRules:
    allowedOrigin: <string>
    allowedHeader: <string>
    allowedMethoded: 
        - POST
        - GET
        - PUT
  retentionPolicy:
    defaultRetentionDay: <integer, must be a number between Maximum Retention Day and Minimum Retention Day>
    maximumRetentionDay: <integer>
    minimumRetentionDay: <integer>

```
#### - Example : Using BindingFrom for Endpoints and ResourceInstanceID 
```
apiVersion: ibmcloud.ibm.com/v1alpha1
kind: Bucket
metadata:
  labels:
    controller-tools.k8s.io: "1.0"
  name: cos4seedb-bucket-014
spec:
  bindingFrom:
      name: cos4seedb 
  bucketname: cos4seedb-bucket-014
  resiliency: regional
  location: us-south
  storageclass: Cold Vault
  corsRules:
    allowedOrigin : "w1.ibm.com"
    allowedHeader : "*"
    allowedMethods :
      - POST
      - GET
      - PUT
  retentionPolicy :
    minimumRetentionDay: 20
    maximumRetentionDay: 40
    defaultRetentionDay: 25
```
#### - Example: Using configMapKeyRef or secretKeyRef

IBM Cloud API Key is stored in Secret:secret4bucket with key:APIKey, resource_instance_id is stored in Secret:cos4seedb with key=resourceInstanceID, endpoints is stored in Config Map: cos4seedbm with key=Endpoints
```
apiVersion: ibmcloud.ibm.com/v1alpha1
kind: Bucket
metadata:
  labels:
    controller-tools.k8s.io: "1.0"
  name: cos4seedb-bucket-014
spec:
  apiKey:
    secretKeyRef:
      name: secret4bucket
      key: APIKey
  resource_instance_id:
    secretKeyRef:
      name: cos4seedb
      key: resourceInstanceID
  endpoints:
    configMapKeyRef:
      name: cos4seedbm
      key: Endpoints
  bucketname: cos4seedb-bucket-014
  ```
#### - Using Key Protect to encrypt objects in a bucket.
  ```
  apiVersion: ibmcloud.ibm.com/v1alpha1
  kind: Bucket
  metadata:
    labels:
      controller-tools.k8s.io: "1.0"
    name: cos4seedb-bucket-jadeyliu-m2c711
  spec:
    resource_instance_id:
      secretKeyRef:
        name: cos4seedb
        key: resource_instance_id
    endpoints:
      configMapKeyRef:
        name: cos4seedbm
        key: endpoints
    bucketname: cos4seedb-bucket-jadeyliu-m2c711
    keyProtect:
      instanceID: ba2be308-91b1-4a9d-b2a9-b23967455d63
      keyName: forcos4seedb
  ```

#### <a name="sampleYaml"></a>- Sample Yaml for creation Service and Binding

```
apiVersion: ibmcloud.ibm.com/v1alpha1
kind: Service
metadata:
  labels:
    controller-tools.k8s.io: "1.0"
  name: cos4seedb
spec:
  externalName: cos4seedb
  serviceClass: cloud-object-storage
  plan: standard
---
apiVersion: ibmcloud.ibm.com/v1alpha1
kind: Binding
metadata:
  name: cos4seedb
spec:
  serviceName: cos4seedb
  role: Manager

```
### <a name="keyprotectSetup"></a>3. Key Protect setup

#### A. Grant service authorization for use with IBM COS

  1. Open your IBM Cloud dashboard
  2. From the menu bar, click Manage > Access (IAM)
  3. On the left panel, click Authorization, click Create
  4. In the Source service menu, select Cloud Object Storage.
  5. In the Source service instance menu, select the service instance to authorize.
  6. In the Target service menu, select IBM Key Protect.
  7. In the Target service instance menu, select the service instance to authorize.
  8. Enable the Reader role.
  9. Click Authorize.

#### B. Create Key Protect using IBM Cloud dashboard

  1. Create a Key Protect instance
  2. Once the instance is instantiated, take note of the instance name
  3. If you have multiple instance with the same name, please use instance ID

```
    ibmcloud resource service-instance <instance name> -id
```

take note of the ID ( in the format of xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx ) of the instance you want to use
add the ID or Name to the Bucket spec for keyProtect

example:

```
  keyProtect:
    instanceID: ba2be308-91b1-4a9d-b2a9-b23967455d63
    keyName: forcos4seedb
```

#### C. Create Key Protect using IBM Cloud Operators

Please refer to [IBM Cloud Operators](https://github.com/ibm/cloud-operators) for detail setup 

Example Yaml file

```
    apiVersion: ibmcloud.ibm.com/v1alpha1
    kind: Service
    metadata:
      labels:
        controller-tools.k8s.io: "1.0"
      name: keyprotect4cos
    spec:
      externalName: keyprotect4cos
      serviceClass: kms
      plan: tiered-pricing
    ---
    apiVersion: ibmcloud.ibm.com/v1alpha1
    kind: Binding
    metadata:
      name: keyprotect4cos
    spec:
      serviceName: keyprotect4cos
      role: Manager
    ---
    apiVersion: ibmcloud.ibm.com/v1alpha1
    kind: Bucket
    metadata:
      labels:
        controller-tools.k8s.io: "1.0"
      name: cos4seedb-bucket-jadeyliu-m2c711
    spec:
      resource_instance_id:
        secretKeyRef:
          name: cos4seedb
          key: resource_instance_id
      endpoints:
        configMapKeyRef:
          name: cos4seedbm
          key: endpoints
      bucketname: cos4seedb-bucket-jadeyliu-m2c711
      keyProtect:
        bindingFrom:
          name: keyprotect4cosa
        keyName: forcos4seedb
```
#### <a name="ibmcloudapikey">D. Create IBM Cloud API Key for KeyProtect Key creation

Key Protect Key creation needs IBM Cloud API Key which is different from the apikey in the IBM Cloud Object Storage's service credential. Use can use the folloging 
script to create both ibmcloud api key and kubernetes secret (replace <APIKeyName> with your key name)

```
ibmcloud iam api-key-create <ApiKeyName> | awk '$1 ~ /API/ && $2 ~ /Key/ { print("apikey=", $3) }' > /tmp/ibmcloudapi.key
k create secret generic <SecretName> --type=Secret --from-env-file=/tmp/ibmcloudapi.key
```

###  <a name="section3"></a>4. How to create Cloud Object Storage Credentials using IBM Cloud Cli

1. Login to IBM Cloud using ibmcloud login

2. Create Credential in Cloud Object Storage instance 

```
  ibmcloud resource service-key-create <credential_name> Manager --instance-name <cos_instance_name>
```
3. Using Secret

    A. Retrieve the Credential, and generate the base64 encoded file (Note: credential_name is from step 1). After the command, you can check if the file `/tmp/mySecret.secrets` is created.

    ```
      ibmcloud resource service-key <credential_name> | 
      awk '/apikey/ {seen = 1} seen {print}' |  
      awk '{system("bash -c '\''echo -n  "$1" | tr : = '\''"); printf("%s \n",$2)}' > /tmp/myCOSSecret.secrets
    ```

    B. Create Secret 

    ```
      kubectl create secret generic <kubebete_secret_name> --type=Secret --from-env-file=/tmp/myCOSSecret.secrets
    ```

4. Using Configmap

    A. create the data file (Note: the attached command create base64 decoded values as ConfigMap will not decode the value automatically)

    ```
      ibmcloud resource service-key cos4seedb-manual  | 
      awk '/apikey/ {seen = 1} seen {print}' |  
      awk '{system("bash -c '\''echo -n  "$1" | tr : = '\''"); system("bash -c '\''echo -n  "$2" | base64 -i -'\''"); printf("\n")}' > /tmp/myCOSSecret.secrets

    ```

    B. Create ConfigMap
    ```
      kubectl create configmap  <kubernete_configmap_name>  --from-env-file=/tmp/myCOSSecret.secrets
    ```

5. Verify the required info is in the Secret or ConfigMap

```
kubectl get secret <kubernete_secret_name> -o yaml
```

For Example, the data field should look like the following (should contains at least apikey, endpoints and resource_instance_id)
```
data:
  apikey: c29tZSByYW5kb20gYXBpa2V5IGdlbmVyYXRlZCBieSB5b3UK
  endpoints: aHR0cHM6Ly9jb250cm9sLmNsb3VkLW9iamVjdC1zdG9yYWdlLmNsb3VkLmlibS5jb20vdjIvZW5kcG9pbnRz
  iam_apikey_description: QXV0by1nZW5lcmF0ZWQ=
  iam_apikey_name: Y29zNHNlZWRiLW1hbnVhbA==
  iam_role_crn: Y3JuOnYxOmJsdWVtaXg6cHVibGljOmlhbTo6OjpzZXJ2aWNlUm9sZTpNYW5hZ2Vy
  iam_serviceid_crn: Y3JuOnYxOmJsdWVtaXg6cHVibGljOmlhbS1pZGVudGl0eTo6YS84OWI3YjllNzliZjYxYTA3OTMxNzlmMTMyMzBmZDJiZDo6c2VydmljZWlkOlNlcnZpY2VJZC02YWU1ZTUwMy00MGU3LTQ3MDQtOTNlMC02Y2NhZTc4NTNmYjM=
  resource_instance_id: Y3JuOnYxOmJsdWVtaXg6cHVibGljOmNsb3VkLW9iamVjdC1zdG9yYWdlOmdsb2JhbDphLzg5YjdiOWU3OWJmNjFhMDc5MzE3OWYxMzIzMGZkMmJkOjQ5OTQ2M2QxLWUwZTYtNGMxYy04YmQzLTIzOTNhZTRjZTRkZTo6
```
