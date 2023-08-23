package client

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/encoding/gcharset"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/text/gregex"
	"github.com/hanbufei/isCdn/config"
	"io/ioutil"
	"net"
	"strings"
	"sync"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/projectdiscovery/retryabledns"
	tx_cdn "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cdn/v20180606"
	tx_common "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tx_profile "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"

	ali_cdn20180510 "github.com/alibabacloud-go/cdn-20180510/v3/client"
	ali_openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ali_util "github.com/alibabacloud-go/tea-utils/v2/service"
	ali_tea "github.com/alibabacloud-go/tea/tea"

	bd_bce "github.com/baidubce/bce-sdk-go/bce"
)

var (
	DefaultCDNProviders   string
	DefaultWafProviders   string
	DefaultCloudProviders string
)

// DefaultResolvers trusted (taken from fastdialer)
var DefaultResolvers = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
}

// Client checks for CDN based IPs which should be excluded
// during scans since they belong to third party firewalls.
type Client struct {
	sync.Once
	cdn          *providerScraper
	waf          *providerScraper
	cloud        *providerScraper
	retriabledns *retryabledns.Client
}

// New creates cdncheck client with default options
// NewWithOpts should be preferred over this function
func New() *Client {
	client, _ := NewWithOpts(3, []string{})
	return client
}

// NewWithOpts creates cdncheck client with custom options
func NewWithOpts(MaxRetries int, resolvers []string) (*Client, error) {
	if MaxRetries <= 0 {
		MaxRetries = 3
	}
	if len(resolvers) == 0 {
		resolvers = DefaultResolvers
	}
	retryabledns, err := retryabledns.New(resolvers, MaxRetries)
	if err != nil {
		return nil, err
	}
	client := &Client{
		cdn:          newProviderScraper(generatedData.CDN),
		waf:          newProviderScraper(generatedData.WAF),
		cloud:        newProviderScraper(generatedData.Cloud),
		retriabledns: retryabledns,
	}
	return client, nil
}

// CheckCDN checks if an IP is contained in the cdn denylist
func (c *Client) CheckCDN(ip net.IP) (matched bool, value string, err error) {
	matched, value, err = c.cdn.Match(ip)
	return matched, value, err
}

// CheckWAF checks if an IP is contained in the waf denylist
func (c *Client) CheckWAF(ip net.IP) (matched bool, value string, err error) {
	matched, value, err = c.waf.Match(ip)
	return matched, value, err
}

// CheckCloud checks if an IP is contained in the cloud denylist
func (c *Client) CheckCloud(ip net.IP) (matched bool, value string, err error) {
	matched, value, err = c.cloud.Match(ip)
	return matched, value, err
}

// GetCityByIp 获取ip所属城市
func (c *Client) GetCityByIp(input net.IP) string {
	ip := input.String()
	if ip == "::1" || ip == "127.0.0.1" {
		return "内网IP"
	}
	url := "http://whois.pconline.com.cn/ipJson.jsp?json=true&ip=" + ip
	bytes := g.Client().GetBytes(context.TODO(), url)
	src := string(bytes)
	srcCharset := "GBK"
	tmp, _ := gcharset.ToUTF8(srcCharset, src)
	json, err := gjson.DecodeToJson(tmp)
	if err != nil {
		return ""
	}
	if json.Get("addr").String() != "" {
		return json.Get("addr").String()
	}
	return fmt.Sprintf("%s %s", json.Get("pro").String(), json.Get("city").String())
}

// 调用腾讯云DescribeCdnIp接口，判断ip是否属于腾讯云
func (c *Client) CheckTencent(input net.IP) (cdn string, isp string) {
	ip := input.String()
	// 实例化一个认证对象，入参需要传入腾讯云账户 SecretId 和 SecretKey，此处还需注意密钥对的保密
	// 密钥可前往官网控制台 https://console.cloud.tencent.com/cam/capi 进行获取
	credential := tx_common.NewCredential(
		config.Config.Tencent.Id,
		config.Config.Tencent.Key,
	)
	cpf := tx_profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "cdn.tencentcloudapi.com"
	// 实例化要请求产品的client对象,clientProfile是可选的
	client, _ := tx_cdn.NewClient(credential, "", cpf)
	// 实例化一个请求对象,每个接口都会对应一个request对象
	request := tx_cdn.NewDescribeCdnIpRequest()
	request.Ips = tx_common.StringPtrs([]string{ip})
	response, err := client.DescribeCdnIp(request)
	//fmt.Print(response.ToJsonString())
	if err != nil {
		return "", ""
	}
	patternStr := `"Platform":"(.*?)"`
	Platform, err := gregex.MatchString(patternStr, response.ToJsonString())
	if err != nil {
		return "", ""
	}
	if Platform[1] == "yes" {
		patternStr = `"Location":"(.*?)"`
		result, reerr := gregex.MatchString(patternStr, response.ToJsonString())
		if reerr != nil {
			return "腾讯云", ""
		}
		return "腾讯云", result[1]
	}
	return "", ""
}

// 调用阿里云DescribeIpInfo接口，判断ip是否属于阿里云
func (c *Client) CheckAliyun(input net.IP) (cdn string, isp string) {
	ip := input.String()
	config := &ali_openapi.Config{
		// 必填，您的 AccessKey ID
		AccessKeyId: ali_tea.String(config.Config.Alibaba.Id),
		// 必填，您的 AccessKey Secret
		AccessKeySecret: ali_tea.String(config.Config.Alibaba.Key),
	}
	config.Endpoint = ali_tea.String("cdn.aliyuncs.com")
	client := &ali_cdn20180510.Client{}
	client, err := ali_cdn20180510.NewClient(config)
	if err != nil {
		return "", ""
	}
	describeIpInfoRequest := &ali_cdn20180510.DescribeIpInfoRequest{IP: ali_tea.String(ip)}
	runtime := &ali_util.RuntimeOptions{}
	response, err := client.DescribeIpInfoWithOptions(describeIpInfoRequest, runtime)
	if err != nil {
		return "", ""
	}
	//fmt.Printf("%s",response.Body.String())
	json, err := gjson.DecodeToJson(response.Body.String())
	if err != nil {
		return "", ""
	}
	if json.Get("CdnIp").String() == "True" {
		return "阿里云", json.Get("ISP").String()
	} else {
		return "", ""
	}
}

// 调用百度云describeIp接口，判断ip是否属于百度云
func (c *Client) CheckBaidu(input net.IP) (cdn string, isp string) {
	ip := input.String()
	req := &bd_bce.BceRequest{}
	req.SetUri("/v2/utils")
	req.SetMethod("GET")
	req.SetParams(map[string]string{"action": "describeIp", "ip": ip})
	req.SetHeaders(map[string]string{"Accept": "application/json"})
	payload, _ := bd_bce.NewBodyFromString("")
	req.SetBody(payload)
	client, err := bd_bce.NewBceClientWithAkSk(config.Config.Baidu.Id, config.Config.Baidu.Key, "https://cdn.baidubce.com")
	if err != nil {
		return "", ""
	}
	resp := &bd_bce.BceResponse{}
	err = client.SendRequest(req, resp)
	if err != nil {
		return "", ""
	}
	respBody := resp.Body()
	defer respBody.Close()
	body, err := ioutil.ReadAll(respBody)
	if err != nil {
		return "", ""
	}
	json, err := gjson.DecodeToJson(string(body))
	if err != nil {
		return "", ""
	}
	if json.Get("cdnIP").String() == "true" {
		return "百度云", json.Get("isp").String()
	} else {
		return "", ""
	}
}

// Check checks if ip belongs to one of CDN, WAF and Cloud . It is generic method for Checkxxx methods
func (c *Client) Check(ip net.IP) (matched bool, value string, itemType string, err error) {
	location := c.GetCityByIp(ip)
	if matched, value, err = c.cdn.Match(ip); err == nil && matched && value != "" {
		return matched, value + "->" + location, "cdn", nil
	}
	if matched, value, err = c.waf.Match(ip); err == nil && matched && value != "" {
		return matched, value + "->" + location, "waf", nil
	}
	if matched, value, err = c.cloud.Match(ip); err == nil && matched && value != "" {
		return matched, value + "->" + location, "cloud", nil
	}
	if cdn, isp := c.CheckTencent(ip); cdn != "" {
		return true, cdn + "->" + location + "->" + isp, "cdn", nil
	}
	if cdn, isp := c.CheckAliyun(ip); cdn != "" {
		return true, cdn + "->" + location + "->" + isp, "cdn", nil
	}
	if cdn, isp := c.CheckBaidu(ip); cdn != "" {
		return true, cdn + "->" + location + "->" + isp, "cdn", nil
	}
	return false, location, "", err
}

// Check Domain with fallback checks if domain belongs to one of CDN, WAF and Cloud . It is generic method for Checkxxx methods
// Since input is domain, as a fallback it queries CNAME records and checks if domain is WAF
func (c *Client) CheckDomainWithFallback(domain string) (matched bool, value string, itemType string, err error) {
	dnsData, err := c.retriabledns.Resolve(domain)
	if err != nil {
		return false, "", "", err
	}
	matched, value, itemType, err = c.CheckDNSResponse(dnsData)
	if err != nil {
		return false, "", "", err
	}
	if matched {
		return matched, value, itemType, nil
	}
	// resolve cname
	dnsData, err = c.retriabledns.CNAME(domain)
	if err != nil {
		return false, "", "", err
	}
	return c.CheckDNSResponse(dnsData)
}

// CheckDNSResponse is same as CheckDomainWithFallback but takes DNS response as input
func (c *Client) CheckDNSResponse(dnsResponse *retryabledns.DNSData) (matched bool, value string, itemType string, err error) {
	if dnsResponse.A != nil {
		for _, ip := range dnsResponse.A {
			ipAddr := net.ParseIP(ip)
			if ipAddr == nil {
				continue
			}
			matched, value, itemType, err := c.Check(ipAddr)
			if err != nil {
				return false, "", "", err
			}
			if matched {
				return matched, value, itemType, nil
			}
		}
	}
	if dnsResponse.CNAME != nil {
		matched, discovered, itemType, err := c.CheckSuffix(dnsResponse.CNAME...)
		if err != nil {
			return false, "", itemType, err
		}
		if matched {
			// for now checkSuffix only checks for wafs
			return matched, discovered, itemType, nil
		}
	}
	return false, "", "", err
}

func MapKeys(m map[string][]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}
