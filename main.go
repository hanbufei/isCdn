package main

import (
	"fmt"
	"github.com/hanbufei/isCdn/client"
	"net"
)

func main() {
	client := client.New()
	var target = []string{"117.23.61.32", "184.51.125.2", "15.230.221.3"}
	for _, ip := range target {
		//检查ip
		matched, val, itemType, _ := client.Check(net.ParseIP(ip))
		if matched {
			fmt.Printf("%v -> %v[%v]\n", ip, itemType, val)
		}
	}
}
