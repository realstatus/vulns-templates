id: cdn-cache-header
info:
  name: 发现CDN缓存头
  author: status
  severity: info
  description: 发现CDN缓存头，可能存在缓存欺骗漏洞
  tags: Cloudflare,cache,scan,finger
  reference:
    - https://mp.weixin.qq.com/s/Anr1WLOSts-uFFpUtJI8Aw
    - https://cloud.tencent.com/developer/article/1516385
    - https://2demo.top/77.html

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
      - "{{RootURL}}/"
    headers:
      User-Agent: Mozilla/5.0 (Linux; Android 7.1.2; MI 5X; Flow) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/347.0.0.268 Mobile Safari/537.36
      Origin: http://127.0.0.1
      Referer:  http://127.0.0.1
    redirects: true
    max-redirects: 3

    matchers:
      - type: dsl
        dsl:
          # - contains(to_lower(header), "cf-cache-status")
          - contains(to_lower(header), '-cache-status')
        condition: or
