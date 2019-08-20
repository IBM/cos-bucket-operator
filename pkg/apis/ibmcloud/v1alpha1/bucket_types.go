/*
Copyright 2019 The Seed Team.

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

package v1alpha1

import (
	v1 "github.com/ibm/cloud-operators/pkg/lib/ibmcloud/v1"
	keyvalue "github.com/ibm/cloud-operators/pkg/lib/keyvalue/v1"
	resv1 "github.com/ibm/cloud-operators/pkg/lib/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// BucketSpec defines the desired state of Bucket
type BucketSpec struct {
	BindingFrom        v1.BindingFrom           `json:"bindingFrom,omitempty"`
	APIKey             *keyvalue.KeyValueSource `json:"apiKey,omitempty"`
	Region             *keyvalue.KeyValueSource `json:"region,omitempty"`
	Endpoints          *keyvalue.KeyValueSource `json:"endpoints,omitempty"`
	ResourceInstanceID *keyvalue.KeyValueSource `json:"resourceInstanceID,omitempty"`
	Resiliency         string                   `json:"resiliency,omitempty"`   // Default to regional
	Location           string                   `json:"location,omitempty"`     // Default to us-south
	BucketType         string                   `json:"bucketType,omitempty"`   // Default to public
	StorageClass       string                   `json:"storageClass,omitempty"` // Default to standard
	KeyProtect         *KeyProtectInfo          `json:"keyProtect,omitempty"`
	CORSRules          CORSRule                 `json:"corsRules,omitempty"`
	KeepIfNotEmpty     bool                     `json:"keepIfNotEmpty,omitempty"` // Default to true
	Context            v1.ResourceContext       `json:"context,omitempty"`
	BindOnly           bool                     `json:"bindOnly,omitempty"` // Default to false
	RetentionPolicy    RetentionPolicy          `json:"retentionPolicy,omitempty"`
}

// ParametersFromSource Parameters value from Source: ConfigMap or Secret
type ParametersFromSource struct {
	// Selects a key of a ConfigMap.
	// +optional
	ConfigMapKeyRef *KeyReference `json:"configMapKeyRef,omitempty"`

	// Selects a key of a secret in the resource namespace
	// +optional
	SecretKeyRef *KeyReference `json:"secretKeyRef,omitempty"`
}

// KeyProtectInfo the KeyProtect Instance can be found from BindingObject specified in BindingFrom, or directly from InstanceName or InstanceID
type KeyProtectInfo struct {
	InstanceName     string                   `json:"instanceName,omitempty"`
	InstanceID       string                   `json:"instanceID,omitempty"`
	InstanceLocation string                   `json:"instanceLocation,omitempty"`
	KeyName          string                   `json:"keyName"`
	BindingFrom      v1.BindingFrom           `json:"bindingFrom,omitempty"`
	APIKey           *keyvalue.KeyValueSource `json:"apiKey,omitempty"`
}

// KeyReference name value pair
type KeyReference struct {
	Name      string `json:"name"`
	Key       string `json:"key"`
	Namespace string `json:"namespace,omitempty"`
}

// CORSRule Rules for CORS
type CORSRule struct {
	AllowedOrigin  string   `json:"allowedOrigin,omitempty"`  // Default to *
	AllowedHeader  string   `json:"allowedHeader,omitempty"`  // Default to *
	AllowedMethods []string `json:"allowedMethods,omitempty"` // Default to Post, Get, Put
}

// RetentionPolicy Policy for Retention
type RetentionPolicy struct {
	MinimumRetentionDay int `json:"minimumRetentionDay,omitempty"`
	MaximumRetentionDay int `json:"maximumRetentionDay,omitempty"`
	DefaultRetentionDay int `json:"defaultRetentionDay,omitempty"`
}

// BucketStatus defines the observed state of Bucket
type BucketStatus struct {
	resv1.ResourceStatus `json:",inline"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Bucket is the Schema for the buckets API
// +k8s:openapi-gen=true
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
type Bucket struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BucketSpec   `json:"spec,omitempty"`
	Status BucketStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BucketList contains a list of Bucket
type BucketList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Bucket `json:"items"`
}

// GetStatus returns the binding status
func (s *Bucket) GetStatus() resv1.Status {
	return &s.Status
}

func init() {
	SchemeBuilder.Register(&Bucket{}, &BucketList{})
}
