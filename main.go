package main

import (
	"fmt"
	"github.com/hanbufei/isCdn/client"
	"net"
)

func main() {
	client := client.New()
	ip := net.ParseIP("117.23.61.32")
	_, val, itemType, _ := client.Check(ip)
	fmt.Printf("%v -> %v[%v]\n", ip, itemType, val)
}
