neustar_wpm: neustar_wpm.c
	gcc -fPIC -shared -o neustar_wpm.so neustar_wpm.c cJSON.c -I../../../include -lcurl -lssl -lcrypto -std=gnu99 -lm
