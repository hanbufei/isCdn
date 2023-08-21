# isCdn
[t00ls社区共创] 检查一个ip是否在cdn范围内
```bigquery
目前已经完成的cdn检测范围：
cloudfront：内置字典
fastly：内置字典
google：内置字典
leaseweb：内置字典
stackpath：内置字典
知道创宇：内置字典
腾讯cdn：官方api -> DescribeCdnIp
阿里cdn：官方api -> DescribeIpInfo
百度cdn：官方api -> describeIp
``` 

#内嵌数据源
```
数据在clinet/data目录下，其中sources_data是国外的数据，sources_china是国内数据。
格式为：
    {"cdn":{"knownsec": []},
    "waf":{},
    "cloud":{}
    }
```

#方式一：直接使用
```bigquery
func main() {
	client := client.New()
	ip := net.ParseIP("117.23.61.32")
	_, val, itemType, _ := client.Check(ip)
	fmt.Printf("%v -> %v[%v]\n", ip, itemType, val)
}
```
运行上面的代码，结果如下：
```bigquery
117.23.61.32 -> cdn[knownsec,陕西省 西安市]
```

#方式二：api调用
```bigquery
在项目里新建cdn目录，并将config.yaml拷贝到改目录下。同时，新建以下go文件，之后调用IsCdn即可。

import (
	_ "embed"
	"github.com/hanbufei/isCdn/client"
	"github.com/hanbufei/isCdn/config"
	"github.com/gogf/gf/v2/encoding/gyaml"
	"log"
	"net"
)

//go:embed config.yaml
var configStr string

func IsCdn(inputIp string)(val string,itemType string){
	err := gyaml.DecodeTo([]byte(configStr), &config.Config)
	if err != nil {
		log.Fatalln(err.Error())
	}
	client := client.New()
	ip := net.ParseIP(inputIp)
	_, val, itemType, _ = client.Check(ip)
	return val,itemType //val是信息，itemType是类型
}
```