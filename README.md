# ns_dup

（应该能）解决奇葩网络环境（校园网）下的 IPv6 ndp relay问题。


## Usage
1. 在OpenWrt路由器配置好ndp relay
2. 运行程序
```sh
ns_dup <WAN_IFACE> <LAN_IFACE>
```

## HOW IT WORKS

抓住发向WAN中的IPv6 NS请求，向LAN区域中转发一遍。

具体问题成因与解决可以参考下面链接中的文章。

### 

## Readings
1. https://wjk.moe/2022/%E9%94%90%E6%8D%B7%E6%A0%A1%E5%9B%AD%E7%BD%91IPv6%E7%9A%84%EF%BC%8F64%E5%86%85%E7%BD%91%E4%B8%AD%E7%BB%A7%E9%85%8D%E7%BD%AE%EF%BC%9Andp-proxy%E3%80%81relay/