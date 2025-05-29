package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	proxy "github.com/macronut/sniproxy/proxy"
)

var ConfigFile string = "config.json"

func StartService() {
	conf, err := os.Open(ConfigFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	bytes, err := io.ReadAll(conf)
	if err != nil {
		log.Panic(err)
	}
	conf.Close()

	var ServiceConfig struct {
		Services []proxy.ServiceConfig `json:"services,omitempty"`
	}

	err = json.Unmarshal(bytes, &ServiceConfig)
	if err != nil {
		log.Panic(err)
	}

	proxy.HostsMap = make(map[string]proxy.ServiceConfig)
	for _, service := range ServiceConfig.Services {
		proxy.HostsMap[service.Name] = service
	}

	l, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Panic(err)
	}

	for {
		client, err := l.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		go proxy.SNIProxy(client)
	}
}

func main() {
	flag.StringVar(&ConfigFile, "c", "config.json", "Config file")
	flag.Parse()
	StartService()
}
