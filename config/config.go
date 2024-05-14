package config

import "fmt"

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

type Result struct {
	Ip       string
	IsMatch  bool   //是否匹配到cdn
	Location string //ip位置
	Type     string //cdn、waf、cloud
	Value    string //值
}

func (r Result) String() string {
	if r.IsMatch {
		return fmt.Sprintf("匹配ip成功！ip:%s location:%s type:%s value:%s", r.Ip, r.Location, r.Type, r.Value)
	}
	return fmt.Sprintf("未找到！ ip:%s location:%s type:%s value:%s", r.Ip, r.Location, r.Type, r.Value)
}
