package config

var Config = struct {
	Tencent struct {
		SecretId  string `yaml:"secretId"`
		SecretKey string `yaml:"secretKey"`
	} `yaml:"Tencent"`
}{}
