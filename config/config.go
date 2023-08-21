package config

var Config = struct {
	Tencent struct {
		Id  string `yaml:"secretId"`
		Key string `yaml:"secretKey"`
	} `yaml:"Tencent"`
	Alibaba struct {
		Id  string `yaml:"accessKeyId"`
		Key string `yaml:"accessKeySecret"`
	} `yaml:"Alibaba"`
}{}
