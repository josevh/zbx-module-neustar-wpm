# Zabbix Loadable Module for Neustar Web Performance Monitoring
### Requirements
- Monitor *descriptions* must contain a unique string to be identified.
  - **my.unique.monitor**
- [OpenSSL](https://www.openssl.org/docs/manmaster/ssl/ssl.html)
  - `#include <openssl/md5.h>`
 - [cJSON](https://sourceforge.net/projects/cjson/)
   - `#include "cJSON.h"`
 - [cURL](https://curl.haxx.se/libcurl/c/)
   - `#include <curl/curl.h>`
### Installation (for server)
1. Clone to modules dir of zabbix source
    - `zabbix_src_dir/src/modules`
2. Make sure that you configure zabbix_src at its root
   - `./configure --enable-static`
3. In module dir, make
   - `zabbix_src_dir/src/modules/neustar_wpm# make`
4. Copy module file to your preferred zabbix module location
   - Server
     - `/usr/lib/zabbix/modules`
5. Update your zabbix config
   - `LoadModulePath=/usr/lib/zabbix/modules`
   - `LoadModule=vmbix.so`
6. Restart zabbix server/agent/etc.
7. On zabbix host, add simple item with key:
   - `neustar_wpm.monitor_status[param1, param2, param3]`
     - param1: Neuster WPM API Key
     - param2: Neustar WPM API secret
     - param3: Unique monitor identifier in description field of monitor

### Return values

| Value         | Status        |
|:-------------:|:------------- |
| 0             | INACTIVE      |
| 1             | SUCCESS       |
| 2             | WARNING       |
| 3             | ERROR         |
