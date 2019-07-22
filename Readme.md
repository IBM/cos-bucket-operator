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
  * Using Binding object: Please reference to the IBM Cloud Operators](https://github.com/ibm/cloud-operators) for installation detail and please see the [sample service and binding yaml](#sampleYaml).
  * To use bucket operator independently, user needs to provide the following information thru kubernetes secrets or configmap. (see [section 2](#section2) for schema information)
    1. apiKey

        a. use the installtaion script 
            ```
            curl -sL https://raw.githubusercontent.com/IBM/cos-bucket-operator/master/hack/install-bucket-operator.sh | bash 
            ```

        b. use an existing IBM Cloud API Key - create either a kubernetes secret or configmap. And then use the following spec to specify where to locate the apiKey
            ```
            apiKey:
              secretKeyRef:
                name: <name of the kubernetes secret>
                key: <the name of the key inside secret identified by name>
            configMapKeyRef:
              name: <name of the configmap>
              key: <the name of the key inside configmap identified by name>
            ```
    2. endpoints - from the Cloud Object Storage credentials. Please see [Section 3](#section3)

    3. resourceInstanceID - from the Cloud Object Storage Credentials.

* If the bucket was removed outside of the Lifecycle of the controller, the bucket will be created with name plus different random strings at the end
* Object inside Bucket will be removed when the deleting the controller, KeepIfNotEmpty flag can be used to avoid accidentally removing of non-empty bucket. With this flag, the Deleting action will fail and will stay in "Deleting" status, until user manual remove the object(s) inside the bucket. Or remove the KeepIfNotEmpty flag from the yaml spec and use `kubectl apply` to change the desired action.
* The location, resilency cannot be changed without removing and recreating the bucket.
* The CORS rules and RetentionPolicy can be changed by using "kubectl apply"
* `bindOnly` is used to bind to existing bucket. You can also use this to change the cors rule and retention policy of existing bucket. Removing the binconly CR will not remove the bucket, but the original CORS rule and Policy will be restored. `Note: Once you create a retention policy it can not be deleted.` To understand the `Retention Policy`, please reference [Immutable Object Storage](https://cloud.ibm.com/docs/services/cloud-object-storage/basics?topic=cloud-object-storage-immutable)  


### <a name="section2"></a>2. Bucket Controller Schema

The Credentials field inside Spec should contains three needed information about where to retrieve the values of `resource_instance_id`, `apikey`, and `endpoints`.
If no keys is defined in the spec of either bindingRef, secretKeyRef or configMapKeyRef, then the operators will try to find all 3 values from it.
If there are duplicate key specified for more than one Ref, the the latter one will overwrite the value in the previous one. The sequence is configMapRef > secretKeyRef > bindingRef. 
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
#### Example : 

In this example, endpoints and resourceInstanceID will be retrieve from the binding object
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
In this example: IBM Cloud API Key is stored in Secret:secret4bucket with key:APIKey, resource_instance_id is stored in Secret:cos4seedb with key=resourceInstanceID, endpoints is stored in Config Map: cos4seedbm with key=Endpoints
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

###  <a name="section3"></a>3. How to create Cloud Object Storage Credentails using IBM Cloud Cli

1. Login to IBM Cloud using ibmcloud login

2. Create Credential in Cloud Object Storage instance 

```
  ibmcloud resource service-key-create <credential_name> Manager --instance-name <cos_instance_name>
```
3. Using Secret

    A. Retrieve the Credential, and generate the base64 encoded file ( Note: credential_name is from step 1). After the command, you can check if the file /tmp/mySecret.secrets is created.

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

For Example, the data field should look like the following ( should contains at least apikey, endpoints and resource_instance_id)
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