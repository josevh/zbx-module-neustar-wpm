# Zabbix Loadable Module for Neustar Web Performance Monitoring

> **NO LONGER MAINTAINED**

> Tested on Zabbix 2.4.4 compiled against 2.4.7 sources.

> Currently, returns monitor statuses only. That is the only data retrieved for now. No other retrieval of data yet implemented but should be trivial using already defined methods.

> Not a `C` programmer. Forgive sloppy code and missing doc blocks. WIP.

> *Help is welcome*.

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
1. Clone repo to modules dir of zabbix source
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
   - `LoadModule=neustar_wpm.so`
6. Restart zabbix server/agent/etc.
7. On zabbix host, add simple item:
   - Key:
     - `neustar_wpm.monitor_status[param1, param2, param3]`
       - **param1**: Neuster WPM API Key
       - **param2**: Neustar WPM API secret
       - **param3**: Unique monitor identifier in description field of monitor
   - Data type:
     - Numeric (unsigned)
   - Interval:
     - Same as update interval of monitor in WPM

### Return values

| Value         | Status        |
|:-------------:|:------------- |
| 0             | INACTIVE      |
| 1             | SUCCESS       |
| 2             | WARNING       |
| 3             | ERROR         |

### Caveats
1. Monitor intervals are varied in WPM. Currently, module is unable to compare whether last sample value received from WPM is same as the last value zabbix received. Therefore, there is room for inaccuracy.
   - To mitigate, zabbix item check intervals should be set to match WPM monitoring intervals. However, WPM may run monitor scripts consecutively after an error in less time than the interval set. There is a good chance that Zabbix may miss or incorrectly determine whether a monitor is actively alerting.
   - If unacceptable, a good solution is to run an external script, instead of using a module, with a small sqlite db that stores the last sample id and compares before sending update to zabbix.
