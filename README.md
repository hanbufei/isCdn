# isCdn
[t00ls社区共创] 检查一个ip是否在cdn范围内

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
运行上面的代码，如果如下：
```bigquery
117.23.61.32 -> cdn[陕西省 西安市,knownsec]
```

#方式二：api调用
```bigquery
import "github.com/hanbufei/isCdn/client"

func demo(ip string)(string,string){
    client := client.New()
    matched,val,itemType,_ := client.Check(net.ParseIP(ip))
    if matched{
        return val,itemType
    }
    return "",""
}
```