package client

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed data/sources_data.json
var sources_data string

//go:embed data/sources_china.json
var sources_china string

var generatedData InputCompiled

func init() {
	if err := json.Unmarshal([]byte(sources_data), &generatedData); err != nil {
		panic(fmt.Sprintf("Could not parse cidr data: %s", err))
	}
	CDNProviders := MapKeys(generatedData.CDN)
	WafProviders := MapKeys(generatedData.WAF)
	CloudProviders := MapKeys(generatedData.Cloud)
	if err := json.Unmarshal([]byte(sources_china), &generatedData); err != nil {
		panic(fmt.Sprintf("Could not parse cidr data: %s", err))
	}
	DefaultCDNProviders = CDNProviders + "," + MapKeys(generatedData.CDN)
	DefaultWafProviders = WafProviders + "," + MapKeys(generatedData.WAF)
	DefaultCloudProviders = CloudProviders + "," + MapKeys(generatedData.Cloud)
}
