package main

import (
	"github.com/bryxxit/steampipe-plugin-puppetdb/puppetdb"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{PluginFunc: puppetdb.Plugin})
}
