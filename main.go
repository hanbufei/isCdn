package main

import (
	"fmt"
	"github.com/hanbufei/isCdn/cmd"
	"github.com/hanbufei/isCdn/config"
)

func main() {
	config := &config.BATconfig{
		TencentId:  "",
		TencentKey: "",
		AlibabaId:  "",
		AlibabaKey: "",
		BaiduId:    "",
		BaiduKey:   ""}

	client := cmd.New(config)
	var ipList = []string{"117.23.61.32", "124.232.162.187", "113.105.168.118", "111.174.1.35", "36.155.132.3"}
	for _, ip := range ipList {
		result := client.Check(ip)
		fmt.Println(result)
	}
}
