/*
Copyright 2016 The Kubernetes Authors.

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

package storagebackend

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/storage/value"
)

const (
	StorageTypeUnset = ""
	StorageTypeETCD2 = "etcd2"
	StorageTypeETCD3 = "etcd3"
)

// Config is configuration for creating a storage backend.
type Config struct {
	// Type defines the type of storage backend, e.g. "etcd2", etcd3". Default ("") is "etcd3".
	Type string
	// Prefix is the prefix to all keys passed to storage.Interface methods.
	Prefix string
	// ServerList is the list of storage servers to connect with.
	ServerList []string
	// TLS credentials
	KeyFile  string
	CertFile string
	CAFile   string
	// Quorum indicates that whether read operations should be quorum-level consistent.
	Quorum bool
	// Paging indicates whether the server implementation should allow paging (if it is
	// supported). This is generally configured by feature gating, or by a specific
	// resource type not wishing to allow paging, and is not intended for end users to
	// set.
	Paging bool
	// DeserializationCacheSize is the size of cache of deserialized objects.
	// Currently this is only supported in etcd2.
	// We will drop the cache once using protobuf.
	DeserializationCacheSize int

	Codec  runtime.Codec
	Copier runtime.ObjectCopier
	// Transformer allows the value to be transformed prior to persisting into etcd.
	Transformer value.Transformer
}

func NewDefaultConfig(prefix string, copier runtime.ObjectCopier, codec runtime.Codec) *Config {
	return &Config{
		Prefix: prefix,
		// Default cache size to 0 - if unset, its size will be set based on target
		// memory usage.
		DeserializationCacheSize: 0,
		Copier: copier,
		Codec:  codec,
	}
}

// TLSConfig creates the tls config from cert file, keyfile and ca file
func (c Config) TLSConfig() *tls.Config {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	if len(c.CertFile) > 0 && len(c.KeyFile) > 0 {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			glog.Errorf("failed to load key pair while getting backends: %s", err)
		} else {
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}
	if len(c.CAFile) > 0 {
		if caCert, err := ioutil.ReadFile(c.CAFile); err != nil {
			glog.Errorf("failed to read ca file while getting backends: %s", err)
		} else {
			caPool := x509.NewCertPool()
			caPool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = caPool
			tlsConfig.InsecureSkipVerify = false
		}
	}
	return tlsConfig
}
