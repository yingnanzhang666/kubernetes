/*
Copyright 2017 The Kubernetes Authors.

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

package preflight

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/golang/glog"
	etcdutil "k8s.io/apiserver/pkg/storage/etcd/util"
)

const (
	tcpTimeout  = 1 * time.Second
	httpTimeout = 20 * time.Second
)

type connection interface {
	serverReachable(address string) bool
	parseServerList(serverList []string) error
	CheckEtcdServers() (bool, error)
}

// EtcdConnection holds the Etcd server list
type EtcdConnection struct {
	ServerList []string
	TLSConfig  *tls.Config
}

func (EtcdConnection) serverReachable(connURL *url.URL) bool {
	scheme := connURL.Scheme
	if scheme == "http" || scheme == "https" || scheme == "tcp" {
		scheme = "tcp"
	}
	if conn, err := net.DialTimeout(scheme, connURL.Host, tcpTimeout); err == nil {
		defer conn.Close()
		return true
	}
	return false
}

func (e EtcdConnection) serverHealthy(connURL *url.URL) bool {
	if connURL == nil {
		return true
	}
	connURL.Path += "/health"
	glog.Infof("check etcd server healthz, connURL: %s", connURL.String())
	req, err := http.NewRequest("GET", connURL.String(), nil)
	if err != nil {
		glog.Errorf("check etcd server healthz, new request err: %s", err)
		return false
	}
	client := http.Client{
		Timeout:   httpTimeout,
		Transport: &http.Transport{TLSClientConfig: e.TLSConfig, DisableKeepAlives: true},
	}
	res, err := client.Do(req)
	if err != nil {
		glog.Errorf("check etcd server healthz, do request err: %s", err)
		return false
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		glog.Errorf("check etcd server healthz, read response err: %s", err)
		return false
	}
	glog.Infof("check etcd server healthz, response body: %s", string(body))
	if res.StatusCode >= http.StatusOK && res.StatusCode < http.StatusBadRequest {
		glog.Infof("status code ok")
		if etcdutil.EtcdHealthCheck(body) == nil {
			glog.Infof("check etcd server healtzh, etcd health check ok.")
			return true
		}
	}
	return false
}

func parseServerURI(serverURI string) (*url.URL, error) {
	connURL, err := url.Parse(serverURI)
	if err != nil {
		return &url.URL{}, fmt.Errorf("unable to parse etcd url: %v", err)
	}
	return connURL, nil
}

// CheckEtcdServers will attempt to reach all etcd servers once. If any
// can be reached, return true.
func (con EtcdConnection) CheckEtcdServers() (done bool, err error) {
	// Attempt to reach every Etcd server in order
	for _, serverURI := range con.ServerList {
		host, err := parseServerURI(serverURI)
		if err != nil {
			return false, err
		}
		if con.serverReachable(host) && con.serverHealthy(host) {
			return true, nil
		}
	}
	return false, nil
}
