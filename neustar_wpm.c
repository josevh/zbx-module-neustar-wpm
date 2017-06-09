#include "sysinc.h"
#include "module.h"
// neustar-wpm module includes
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <curl/curl.h>
#include <string.h>     //strcat
#include <openssl/md5.h>
#include "cJSON.h"
#include <unistd.h>

 //TODO: Dynamic allocation of char arrays

// neustar_wpm module declarations
struct MemoryStruct {
    char *memory;
    size_t size;
};
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
void httpGet(const char* url, char* curl_ret);
void getMonitorID(const char *curl_ret, const char *key, char *monitor_id);
void makeURL(char* fullURL, const char api_key[], const char api_secret[], const char service[], const char method[]);
void getLastStatus(const char *curl_ret, char* status);
void makeSig(const char api_key[], const char api_secret[], char *signature);
int monitor_status(const char api_key[], const char api_secret[], const char monitor_key[]);

/* the variable keeps timeout setting for item processing */
static int	item_timeout = 0;

int	zbx_module_neustar_monitor_status(AGENT_REQUEST *request, AGENT_RESULT *result);

static ZBX_METRIC keys[] =
/*      KEY                     FLAG		FUNCTION        	TEST PARAMETERS */
{
	{"neustar_wpm.monitor_status",	CF_HAVEPARAMS,	zbx_module_neustar_monitor_status,	NULL},
	{NULL}
};

/******************************************************************************
 *                                                                            *
 * Function: zbx_module_api_version                                           *
 *                                                                            *
 * Purpose: returns version number of the module interface                    *
 *                                                                            *
 * Return value: ZBX_MODULE_API_VERSION_ONE - the only version supported by   *
 *               Zabbix currently                                             *
 *                                                                            *
 ******************************************************************************/
int	zbx_module_api_version()
{
	return ZBX_MODULE_API_VERSION_ONE;
}

/******************************************************************************
 *                                                                            *
 * Function: zbx_module_item_timeout                                          *
 *                                                                            *
 * Purpose: set timeout value for processing of items                         *
 *                                                                            *
 * Parameters: timeout - timeout in seconds, 0 - no timeout set               *
 *                                                                            *
 ******************************************************************************/
void	zbx_module_item_timeout(int timeout)
{
	item_timeout = timeout;
}

/******************************************************************************
 *                                                                            *
 * Function: zbx_module_item_list                                             *
 *                                                                            *
 * Purpose: returns list of item keys supported by the module                 *
 *                                                                            *
 * Return value: list of item keys                                            *
 *                                                                            *
 ******************************************************************************/
ZBX_METRIC	*zbx_module_item_list()
{
	return keys;
}

int	zbx_module_neustar_monitor_status(AGENT_REQUEST *request, AGENT_RESULT *result)
{
	char	*api_key, *api_secret, *monitor_key;

	if (3 != request->nparam)
	{
		SET_MSG_RESULT(result, strdup("Invalid number of parameters."));
		return SYSINFO_RET_FAIL;
	}

	api_key = get_rparam(request, 0);
	api_secret = get_rparam(request, 1);
	monitor_key = get_rparam(request, 2);

    char service[] = "/monitor";
    char method[] = "";
    char monitorURL[156];
    makeURL(monitorURL, api_key, api_secret, service, method);

    char monitors[1024*32];
    httpGet(monitorURL, monitors);

    if (strcmp("CURL_ERROR", monitors) != 0) {
        char monitor_id[128];
        getMonitorID(monitors, monitor_key, monitor_id);
        if (strcmp(monitor_id, "JSON_FAILURE") != 0) {
            char method2[48];
            strcpy(method2, "/");
            strcat(method2, monitor_id);
            strcat(method2, "/summary");
            char summaryURL[156];
            makeURL(summaryURL, api_key, api_secret, service, method2);

            char summary[1024*2]; //TODO: Dynamic allocation
            httpGet(summaryURL, summary);
            if (strcmp("CURL_ERROR", summary) != 0) {
                char status[16];
                getLastStatus(summary, status);
                if (strcmp(status, "JSON_FAILURE") != 0) {
                    if (strcmp(status, "SUCCESS") == 0) {
                        SET_UI64_RESULT(result, 1);
                    } else if (strcmp(status, "WARNING") == 0) {
                        SET_UI64_RESULT(result, 2);
                    } else if (strcmp(status, "ERROR") == 0) {
                        SET_UI64_RESULT(result, 3);
                    } else if (strcmp(status, "INACTIVE") == 0) {
                        SET_UI64_RESULT(result, 0);
                    } else {
                        SET_MSG_RESULT(result, strdup("Unexpected return from Neustar."));
                        return SYSINFO_RET_FAIL;
                    }
                    return SYSINFO_RET_OK;
                }
            }
        }
    }
	SET_MSG_RESULT(result, strdup("Unable to communicate with Neustar successfully."));
	return SYSINFO_RET_FAIL;
}

/******************************************************************************
 *                                                                            *
 * Function: zbx_module_init                                                  *
 *                                                                            *
 * Purpose: the function is called on agent startup                           *
 *          It should be used to call any initialization routines             *
 *                                                                            *
 * Return value: ZBX_MODULE_OK - success                                      *
 *               ZBX_MODULE_FAIL - module initialization failed               *
 *                                                                            *
 * Comment: the module won't be loaded in case of ZBX_MODULE_FAIL             *
 *                                                                            *
 ******************************************************************************/
int	zbx_module_init()
{
	/* initialization for dummy.random */
	srand(time(NULL));

	return ZBX_MODULE_OK;
}


/******************************************************************************
 *                                                                            *
 * Function: zbx_module_uninit                                                *
 *                                                                            *
 * Purpose: the function is called on agent shutdown                          *
 *          It should be used to cleanup used resources if there are any      *
 *                                                                            *
 * Return value: ZBX_MODULE_OK - success                                      *
 *               ZBX_MODULE_FAIL - function failed                            *
 *                                                                            *
 ******************************************************************************/
int	zbx_module_uninit()
{
	return ZBX_MODULE_OK;
}

void makeSig(const char api_key[], const char api_secret[], char *signature)
{
    char sig[100];
    // generate string timestamp
    int timestamp = (int)time(NULL);
    char str_timestamp[20];
    sprintf(str_timestamp, "%9d", timestamp);

    // generate sig string
    strcpy(sig, api_key);
    strcat(sig, api_secret);
    strcat(sig, str_timestamp);

    //generate MD5 hash
    unsigned char md5Hash[MD5_DIGEST_LENGTH];
    MD5(sig, strlen(sig), md5Hash);
    // store hash
    char sigMD5[32];
    for(int i = 0; i < 16; ++i)
        sprintf(&sigMD5[i*2], "%02x", md5Hash[i]);
    strcpy(signature, sigMD5);
}

void getLastStatus(const char *curl_ret, char* status)
{
    cJSON * json_root = cJSON_Parse(curl_ret);
    if (!json_root) {
        strcpy(status, "JSON_FAILURE");
    } else {
        cJSON * json_data = cJSON_GetObjectItem(json_root,"data");
        cJSON * json_items = cJSON_GetObjectItem(json_data,"items");
        cJSON * json_items_child = cJSON_GetArrayItem(json_items, 0);
        if (strcmp(cJSON_GetObjectItem(json_items_child, "status")->valuestring, "Off") != 0) {
            strcpy(status, cJSON_GetObjectItem(json_items_child, "generalStatus")->valuestring);
        } else {
            strcpy(status, "INACTIVE");
        }
    }
    cJSON_Delete(json_root);
}

void makeURL(char* fullURL, const char api_key[], const char api_secret[], const char service[], const char method[])
{
    char sig[100];
    makeSig(api_key, api_secret, sig);
    // prep url
    const char baseURL[] = "http://api.sec.neustar.biz/performance";
    const char version[] = "/1.0";
    strcpy(fullURL, baseURL);
    strcat(fullURL, service);
    strcat(fullURL, version);
    strcat(fullURL, method);
    strcat(fullURL, "?apikey=");
    strcat(fullURL, api_key);
    strcat(fullURL, "&sig=");
    strcat(fullURL, sig);
}

void getMonitorID(const char *curl_ret, const char *key, char *monitor_id)
{
    int check = 0;
    cJSON * json_root = cJSON_Parse(curl_ret);
    if (!json_root) {
        strcpy(monitor_id, "JSON_FAILURE");
    } else {
        cJSON * json_data = cJSON_GetObjectItem(json_root,"data");
        cJSON * json_items = cJSON_GetObjectItem(json_data,"items");
        cJSON * json_items_child = cJSON_GetArrayItem(json_items, 0);
        while (json_items) {
            cJSON *monitor = json_items->child;
            while (monitor) {
                if (cJSON_GetObjectItem(monitor, "description")) {
                    if (strcmp(cJSON_GetObjectItem(monitor, "description")->valuestring, key) == 0) {
                        strcpy(monitor_id, cJSON_GetObjectItem(monitor, "id")->valuestring);
                        check = 1;
                        break;
                    }
                }
                monitor = monitor->next;
            }
            if (check == 0) {
                json_items = json_items->next;
            } else {
                break;
            }
        }
        cJSON_Delete(json_root);
    }
}

void httpGet(const char* url, char* curl_ret)
{
    CURL *curl_handle;
    CURLcode res;

    struct MemoryStruct chunk;

    chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
    chunk.size = 0;    /* no data at this point */

    curl_global_init(CURL_GLOBAL_ALL);

    /* init the curl session */
    curl_handle = curl_easy_init();

    /* specify URL to get */
    curl_easy_setopt(curl_handle, CURLOPT_URL, url);

    curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, 1);

    /* send all data to this function  */
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

    /* some servers don't like requests that are made without a user-agent
     field, so we provide one */
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    /* get it! */
    int count = 0;
    do {
        res = curl_easy_perform(curl_handle);
        count = count + 1;
        if (res != CURLE_OK) {
            sleep(1);
        }
    } while(res != CURLE_OK && count < 10);

    /* check for errors */
    if(res != CURLE_OK) {
        strcpy(curl_ret, "CURL_ERROR");
        // fprintf(stderr, "count: %d\n", count);
        // fprintf(stderr, "curl_easy_perform() failed: %s\n",
        //         curl_easy_strerror(res));
    } else {
        // fprintf(stderr, "count: %d\n", count);
        strcpy(curl_ret, chunk.memory);
        /*
         * Now, our chunk.memory points to a memory block that is chunk.size
         * bytes big and contains the remote file.
         *
         * Do something nice with it!
         */
        // printf("%s\n", chunk.memory);
        //  printf("%lu bytes retrieved\n", (long)chunk.size);
    }

    /* cleanup curl stuff */
    curl_easy_cleanup(curl_handle);

    free(chunk.memory);

    /* we're done with libcurl, so clean it up */
    curl_global_cleanup();
}

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    /* out of memory! */
    // printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}
