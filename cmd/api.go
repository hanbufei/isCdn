package cmd

import (
	_ "embed"
	"github.com/hanbufei/isCdn/client"
)

type BATconfig struct {
	//密钥可前往官网控制台 https://console.cloud.tencent.com/cam/capi 进行获取
	TencentId  string
	TencentKey string
	//密钥可前往官网控制台 https://ram.console.aliyun.com/manage/ak 进行获取
	AlibabaId  string
	AlibabaKey string
	//密钥可前往官网控制台 https://console.bce.baidu.com/iam 进行获取
	BaiduId  string
	BaiduKey string
}

type CdnCheck struct {
	client *client.Client
}

func New(config *BATconfig) CdnCheck {
	return CdnCheck{client: client.New(config)}
}

func (c *CdnCheck) Check(ip string) string {
	matched, val, itemType, err := c.client.Check(ip)
	if !matched {
		return err.Error()
	}
	return itemType + val
}
