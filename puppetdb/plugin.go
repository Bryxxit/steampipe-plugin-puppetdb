package puppetdb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/turbot/steampipe-plugin-sdk/plugin"
	"github.com/turbot/steampipe-plugin-sdk/plugin/transform"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
)

func Plugin(ctx context.Context) *plugin.Plugin {
	p := &plugin.Plugin{
		Name:             "steampipe-plugin-puppetdb",
		DefaultTransform: transform.FromGo().NullIfZero(),
		TableMap: map[string]*plugin.Table{
			"puppetdb_node": tablePuppetDBNodes(),
		},
	}
	return p
}

var NODES_ENDPONT = "/pdb/query/v4/nodes"

type Client struct {
	BaseURL    string
	Cert       string
	Key        string
	httpClient *http.Client
	verbose    bool
}

type NodeJson struct {
	Certname                string `json:"certname"`
	Deactivated             string `json:"deactivated,omitempty"`
	Expired                 string `json:"expired,omitempty"`
	CatalogTimestamp        string `json:"catalog_timestampv"`
	FactsTimestamp          string `json:"facts_timestamp,omitempty"`
	ReportTimestamp         string `json:"report_timestamp,omitempty"`
	CatalogEnvironment      string `json:"catalog_environment,omitempty"`
	FactsEnvironment        string `json:"facts_environment,omitempty"`
	ReportEnvironment       string `json:"report_environment,omitempty"`
	LatestReportStatus      string `json:"latest_report_status"`
	LatestReportNoop        bool   `json:"latest_report_noop"`
	LatestReportNoopPending bool   `json:"latest_report_noop_pending"`
	LatestReportHash        string `json:"latest_report_hash"`
	LatestReportJobID       string `json:"latest_report_job_id,omitempty"`
	// Report                  ReportJSON `json:"report,omitempty"`
}

func tablePuppetDBNodes() *plugin.Table {
	return &plugin.Table{
		Name:        "puppetdb_nodes",
		Description: "Retrieve information about PuppetDB nodes.",
		List: &plugin.ListConfig{
			Hydrate: listPuppetDBNodes,
		},
		Columns: []*plugin.Column{
			{Name: "certname", Type: proto.ColumnType_STRING, Description: "The certificate name of the node"},
			{Name: "deactivated", Type: proto.ColumnType_STRING, Description: "The deactivation timestamp of the node"},
			{Name: "expired", Type: proto.ColumnType_STRING, Description: "The expiration timestamp of the node"},
			{Name: "catalog_timestamp", Type: proto.ColumnType_STRING, Description: "The catalog timestamp of the node"},
			{Name: "facts_timestamp", Type: proto.ColumnType_STRING, Description: "The facts timestamp of the node"},
			{Name: "report_timestamp", Type: proto.ColumnType_STRING, Description: "The report timestamp of the node"},
			{Name: "catalog_environment", Type: proto.ColumnType_STRING, Description: "The catalog environment of the node"},
			{Name: "facts_environment", Type: proto.ColumnType_STRING, Description: "The facts environment of the node"},
			{Name: "report_environment", Type: proto.ColumnType_STRING, Description: "The report environment of the node"},
			{Name: "latest_report_status", Type: proto.ColumnType_STRING, Description: "The status of the latest report"},
			{Name: "latest_report_noop", Type: proto.ColumnType_BOOL, Description: "Whether the latest report was a noop"},
			{Name: "latest_report_noop_pending", Type: proto.ColumnType_BOOL, Description: "Whether the latest report has noop pending"},
			{Name: "latest_report_hash", Type: proto.ColumnType_STRING, Description: "The hash of the latest report"},
			{Name: "latest_report_job_id", Type: proto.ColumnType_STRING, Description: "The job ID of the latest report"},
		},
	}
}

func listPuppetDBNodes(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	config := getConfig()
	client := NewClient(config, false)
	nodes, err := client.getNodesJson()
	if err != nil {
		return nil, err
	}
	for _, node := range nodes {
		d.StreamListItem(ctx, node)
	}
	return nil, nil
}

func (client *Client) getNodesJson() ([]NodeJson, error) {
	uri := client.BaseURL + NODES_ENDPONT

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status code %d", resp.StatusCode)
	}

	var nodes []NodeJson
	err = json.NewDecoder(resp.Body).Decode(&nodes)
	if err != nil {
		return nil, err
	}

	return nodes, nil
}

// getURL return the address of the puppetdb instance.
func getURL(host string, port int, ssl bool) string {
	if ssl {
		return fmt.Sprintf("https://%s:%v", host, port)
	} else {
		return fmt.Sprintf("http://%s:%v", host, port)
	}
}

type Conf struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	SSL  bool   `yaml:"ssl"`
	Key  string `yaml:"key"`
	Ca   string `yaml:"ca"`
	Cert string `yaml:"cert"`
}

func getConfig() *Conf {
	host := os.Getenv("PUPPETDB_HOST")
	port := os.Getenv("PUPPETDB_PORT")
	portI := 8080
	key := os.Getenv("PUPPETDB_KEY")
	cert := os.Getenv("PUPPETDB_CERT")
	ca := os.Getenv("PUPPETDB_CA")

	if host == "" {
		host = "localhost"
	}
	if port != "" {
		portI, _ = strconv.Atoi(port)
	}

	sslCheck := false
	if key != "" && cert != "" && ca != "" {
		sslCheck = true
	}
	return &Conf{
		Host: host,
		Port: portI,
		SSL:  sslCheck,
		Key:  key,
		Cert: cert,
		Ca:   ca,
	}
}

func NewClient(conf *Conf, verbose bool) *Client {
	host := conf.Host
	port := conf.Port
	key := conf.Key
	cert := conf.Cert
	ca := conf.Ca
	if !conf.SSL {
		client := &http.Client{}
		return &Client{getURL(host, port, false), "", "", client, verbose}
	}
	if key == "" || cert == "" || ca == "" {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		client := &http.Client{Transport: tr}
		return &Client{getURL(host, port, true), "", "", client, verbose}
	}

	flag.Parse()
	cert2, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		log.Println(err.Error())
	}
	// Load CA cert
	caCert, err := ioutil.ReadFile(ca)
	if err != nil {
		log.Println(err.Error())
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert2},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}
	return &Client{getURL(host, port, true), cert, key, client, verbose}
}
