package main

import (
	"fmt"
	"github.com/gogf/gf/v2/encoding/gyaml"
	"github.com/hanbufei/isCdn/client"
	"github.com/hanbufei/isCdn/config"
	"io/ioutil"
	"log"
	"net"
)

func main() {
	var ConfigBody, err = ioutil.ReadFile("./config.yaml")
	if err != nil {
		log.Fatalln(err.Error())
	}
	err = gyaml.DecodeTo(ConfigBody, &config.Config)
	if err != nil {
		log.Fatalln(err.Error())
	}

	//var input string
	//flag.StringVar(&input, "ip", "127.0.0.1", "输入ip")
	//flag.Parse()
	//ip := net.ParseIP(input)//"117.23.61.32"

	client := client.New()
	var ipList = []string{"117.23.61.32", "124.232.162.187", "113.105.168.118"}
	for _, i := range ipList {
		ip := net.ParseIP(i)
		_, val, itemType, _ := client.Check(ip)
		fmt.Printf("%v -> %v[%v]\n", ip, itemType, val)
	}
}
