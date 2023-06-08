# ModSecParse

A horribly written Python script to rapidly scan [ModSecurity](https://github.com/SpiderLabs/ModSecurity) logs for attacks against a given parameter

## Usage

Pretty self-explanatory. For the `ATTACK` argument choose one of `SQLI`,`XSS`,`RFI`,`LFI`,`RCE`,`PHPI`,`HTTP`,`SESS`

```
$ python3 modsec_log_parser.py                              
Parse ModSecurity log and show messages where a given attack was detected against a given parameter

Usage: modsec_log_parser.py <logfile> <param> <ATTACK> [verbose]
   eg: modsec_log_parser.py modsec_audit.log pollid  SQLI
```

## Examples

Find RCE attacks against (body) parameter "pollid"
```bash
$ python3 modsec_log_parser.py modsec_audit.log pollid RCE
ts:07/Jun/2023:18:22:37 src:192.168.210.50 atk:RCE par:pollid
```

Find SQL injections attacks against "action"
```bash              
$ python3 modsec_log_parser.py modsec_audit.log action SQLI 
ts:07/Jun/2023:18:22:37 src:192.168.210.50 atk:SQLI par:action
ts:07/Jun/2023:18:56:49 src:192.168.210.50 atk:SQLI par:action
ts:07/Jun/2023:18:56:50 src:192.168.210.50 atk:SQLI par:action
...
```

Show me all the H part's header (long but `cut`-friendly tho)
```bash
$ python3 modsec_log_parser.py modsec_audit.log pollid SQLI verbose       
ts:07/Jun/2023:18:22:37 src:192.168.210.50 atk:SQLI par:pollid Message: Warning. Matched phrase "sqlmap" at REQUEST_HEADERS:User-Agent. [file "/usr/share/modsecurity-crs/rules/REQUEST-913-SCANNER-DETECTION.conf"] [line "55"] [id "913100"] [msg "Found User-Agent associated with security scanner"] [data "Matched Data: sqlmap found within REQUEST_HEADERS:User-Agent: sqlmap/1.5.10#stable (https://sqlmap.org)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.2.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-reputation-scanner"] [tag "OWASP_CRS"] [tag "OWASP_CRS/AUTOMATION/SECURITY_SCANNER"] [tag "WASCTC/WASC-21"] [tag "OWASP_TOP_10/A7"] [tag "PCI/6.5.10"]
ts:07/Jun/2023:18:56:49 src:192.168.210.50 atk:SQLI par:pollid Message: Warning. Matched phrase "sqlmap" at REQUEST_HEADERS:User-Agent. [file "/usr/share/modsecurity-crs/rules/REQUEST-913-SCANNER-DETECTION.conf"] [line "55"] [id "913100"] [msg "Found User-Agent associated with security scanner"] [data "Matched Data: sqlmap found within REQUEST_HEADERS:User-Agent: sqlmap/1.5.10#stable (https://sqlmap.org)"] [severity "CRITICAL"] [ver "OWASP_CRS/3.2.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-reputation-scanner"] [tag "OWASP_CRS"] [tag "OWASP_CRS/AUTOMATION/SECURITY_SCANNER"] [tag "WASCTC/WASC-21"] [tag "OWASP_TOP_10/A7"] [tag "PCI/6.5.10"]
...

$ python3 modsec_log_parser.py modsec_audit.log pollid RCE verbose | wc -l
1
```

## Credits

- [@elmehalawi](https://github.com/elmehalawi) for [modsecurity-parser](https://github.com/elmehalawi/modsecurity-parser/blob/master/parser.py) 

- [@fymemon](https://twitter.com/fymemon) for [this nginx.com blog](https://www.nginx.com/blog/modsecurity-logging-and-debugging/#Audit-Log) which is a ModSecurity nice reference