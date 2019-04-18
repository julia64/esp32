/* Scan Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

/*
    This example shows how to use the All Channel Scan or Fast Scan to connect
    to a Wi-Fi network.

    In the Fast Scan mode, the scan will stop as soon as the first network matching
    the SSID is found. In this mode, an application can set threshold for the
    authentication mode and the Signal strength. Networks that do not meet the
    threshold requirements will be ignored.

    In the All Channel Scan mode, the scan will end only after all the channels
    are scanned, and connection will start with the best network. The networks
    can be sorted based on Authentication Mode or Signal Strength. The priority
    for the Authentication mode is:  WPA2 > WPA > WEP > Open
*/
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "soc/rtc_cntl_reg.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "tcpip_adapter.h"
#include "lwip/api.h"
#include "esp_err.h"


#if CONFIG_WIFI_ALL_CHANNEL_SCAN
#define DEFAULT_SCAN_METHOD WIFI_ALL_CHANNEL_SCAN
#elif CONFIG_WIFI_FAST_SCAN
#define DEFAULT_SCAN_METHOD WIFI_FAST_SCAN
#else
#define DEFAULT_SCAN_METHOD WIFI_FAST_SCAN
#endif /*CONFIG_SCAN_METHOD*/

#if CONFIG_WIFI_CONNECT_AP_BY_SIGNAL
#define DEFAULT_SORT_METHOD WIFI_CONNECT_AP_BY_SIGNAL
#elif CONFIG_WIFI_CONNECT_AP_BY_SECURITY
#define DEFAULT_SORT_METHOD WIFI_CONNECT_AP_BY_SECURITY
#else
#define DEFAULT_SORT_METHOD WIFI_CONNECT_AP_BY_SIGNAL
#endif /*CONFIG_SORT_METHOD*/

#if CONFIG_FAST_SCAN_THRESHOLD
#define DEFAULT_RSSI CONFIG_FAST_SCAN_MINIMUM_SIGNAL
#if CONFIG_EXAMPLE_OPEN
#define DEFAULT_AUTHMODE WIFI_AUTH_OPEN
#elif CONFIG_EXAMPLE_WEP
#define DEFAULT_AUTHMODE WIFI_AUTH_WEP
#elif CONFIG_EXAMPLE_WPA
#define DEFAULT_AUTHMODE WIFI_AUTH_WPA_PSK
#elif CONFIG_EXAMPLE_WPA2
#define DEFAULT_AUTHMODE WIFI_AUTH_WPA2_PSK
#else
#define DEFAULT_AUTHMODE WIFI_AUTH_OPEN
#endif
#else
#define DEFAULT_RSSI -127
#define DEFAULT_AUTHMODE WIFI_AUTH_OPEN
#endif /*CONFIG_FAST_SCAN_THRESHOLD*/

typedef struct {
    uint8_t header[4];
    uint8_t dest_mac[6];
    uint8_t source_mac[6];
    uint8_t bssid[6];
    uint8_t payload[0];
} sniffer_payload_t;

typedef struct station_info {
    uint8_t  bssid[6];
    int8_t   rssi;
    uint8_t  channel;
    uint32_t timestamp;
    struct   station_info *next;
} station_info_t;

#define TCP_Client_RX_BUFSIZE 199

static const uint8_t esp_module_mac[32][3] = {
    {0x54, 0x5A, 0xA6}, {0x24, 0x0A, 0xC4}, {0xD8, 0xA0, 0x1D}, {0xEC, 0xFA, 0xBC},
    {0xA0, 0x20, 0xA6}, {0x90, 0x97, 0xD5}, {0x18, 0xFE, 0x34}, {0x60, 0x01, 0x94},
    {0x2C, 0x3A, 0xE8}, {0xA4, 0x7B, 0x9D}, {0xDC, 0x4F, 0x22}, {0x5C, 0xCF, 0x7F},
    {0xAC, 0xD0, 0x74}, {0x30, 0xAE, 0xA4}, {0x24, 0xB2, 0xDE}, {0x68, 0xC6, 0x3A},
};

const static int CONNECTED_BIT = BIT0;
int s_device_info_num           = 0;
station_info_t *station_info    = NULL;
station_info_t *g_station_list  = NULL;

static EventGroupHandle_t s_wifi_event_group;


static inline uint32_t sniffer_timestamp()
{
    return xTaskGetTickCount() * (1000 / configTICK_RATE_HZ);
}
/* The callback function of sniffer */
void wifi_sniffer_cb(void *recv_buf, wifi_promiscuous_pkt_type_t type)
{
    wifi_promiscuous_pkt_t *sniffer = (wifi_promiscuous_pkt_t *)recv_buf;
    sniffer_payload_t *sniffer_payload = (sniffer_payload_t *)sniffer->payload;

    /* Check if the packet is Probo Request  */
    if (sniffer_payload->header[0] != 0x40) {
        return;
    }

    if (!g_station_list) {
        g_station_list = malloc(sizeof(station_info_t));
        g_station_list->next = NULL;
    }

    /* Check if there is enough memoory to use */
    if (esp_get_free_heap_size() < 60 * 1024) {
        s_device_info_num = 0;

        for (station_info = g_station_list->next; station_info; station_info = g_station_list->next) {
            g_station_list->next = station_info->next;
            free(station_info);
        }
    }
    /* Filter out some useless packet  */
    for (int i = 0; i < 32; ++i) {
        if (!memcmp(sniffer_payload->source_mac, esp_module_mac[i], 3)) {
            return;
        }
    }
    /* Traversing the chain table to check the presence of the device */
    for (station_info = g_station_list->next; station_info; station_info = station_info->next) {
        if (!memcmp(station_info->bssid, sniffer_payload->source_mac, sizeof(station_info->bssid))) {
            return;
        }
    }
    /* Add the device information to chain table */
    if (!station_info) {
        station_info = malloc(sizeof(station_info_t));
        station_info->next = g_station_list->next;
        g_station_list->next = station_info;
    }

    station_info->rssi = sniffer->rx_ctrl.rssi;
    station_info->channel = sniffer->rx_ctrl.channel;
    station_info->timestamp = sniffer_timestamp();
    memcpy(station_info->bssid, sniffer_payload->source_mac, sizeof(station_info->bssid));
    s_device_info_num++;
    printf("\nCurrent device num = %d\n", s_device_info_num);
    printf("MAC: 0x%02X.0x%02X.0x%02X.0x%02X.0x%02X.0x%02X, The time is: %d, The rssi = %d\n", station_info->bssid[0], station_info->bssid[1], station_info->bssid[2], station_info->bssid[3], station_info->bssid[4], station_info->bssid[5], station_info->timestamp, station_info->rssi);
}

void TCP_Client(void *pvParameter)
{
    uint32_t date_len=0;
    esp_err_t err,recv_err;
    static u16_t server_port,local_port;
    static ip_addr_t server_ipaddr,loca_ipaddr;
    struct pbuf *q;
    struct netconn *tcp_clientconn;
    char tcp_client_sendbuf[200]="OK123123hahahaha";
    char tcp_client_recvbuf[200];
    //xEventGroupWaitBits(s_wifi_event_group,CONNECTED_BIT,false,true,protMAX_DELAY);
    LWIP_UNUSED_ARG(pvParameter);
    server_port=12345;
    IP4_ADDR(&(server_ipaddr.u_addr.ip4),67,216,211,146);
    while(1)
    {
        tcp_clientconn = netconn_new(NETCONN_TCP);
        
        err = netconn_connect(tcp_clientconn,&server_ipaddr,server_port);
        
        if( err!=ERR_OK )
        {
            netconn_delete(tcp_clientconn);
        }    
        else if(err == ERR_OK)
        {
            tcp_clientconn->recv_timeout=10;
            netconn_getaddr(tcp_clientconn,&loca_ipaddr,&local_port,1);
            printf("Connect server\r\n");
            while(1)
            {
                struct netbuf *recvbuf;
                err = netconn_write(tcp_clientconn,tcp_client_sendbuf,strlen((char *)tcp_client_sendbuf),NETCONN_COPY);
                if(err!= ERR_OK)
                {
                    printf("Send error\r\n");
                }
                if((recv_err=netconn_recv(tcp_clientconn,&recvbuf))==ERR_OK)
                {
                    memset(tcp_client_recvbuf,0,TCP_Client_RX_BUFSIZE);
                    for(q=recvbuf->p;q!=NULL;q=q->next)
                    {
                        if(q->len>(TCP_Client_RX_BUFSIZE-date_len))memcpy(tcp_client_recvbuf+date_len,q->payload,(TCP_Client_RX_BUFSIZE-date_len));
                        else memcpy(tcp_client_recvbuf+date_len,q->payload,q->len);
                        date_len+=q->len;
                        if(date_len > TCP_Client_RX_BUFSIZE)break;
                        
                    }
                    date_len=0;
                    printf("%s\r\n", tcp_client_recvbuf);
                    netbuf_delete(recvbuf);
                    
                }
                else if(recv_err==ERR_CLSD)
                {
                    netconn_close(tcp_clientconn);
                    netconn_delete(tcp_clientconn);
                    printf("Close server\r\n");
                    break;
                }
                
            }
        }
		vTaskDelay(1000/portTICK_PERIOD_MS);
    }
}

static const char *TAG = "scan";

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch (event->event_id) {
        case SYSTEM_EVENT_STA_START:
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_START");
            ESP_ERROR_CHECK(esp_wifi_connect());
            break;
        case SYSTEM_EVENT_STA_GOT_IP:
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_GOT_IP");
            ESP_LOGI(TAG, "Got IP: %s\n",
                     ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
                     
            xTaskCreate(TCP_Client, "server", 2048, NULL, (tskIDLE_PRIORITY + 2), NULL);
			//xEventGroupSetBits(s_wifi_event_group, CONNECTED_BIT);
			//if (!g_station_list) {
			//	g_station_list = malloc(sizeof(station_info_t));
			//	g_station_list->next = NULL;
			//	ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb));
			//	ESP_ERROR_CHECK(esp_wifi_set_promiscuous(1));
			//}
                     
            break;
        case SYSTEM_EVENT_STA_DISCONNECTED:
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_DISCONNECTED");
            ESP_ERROR_CHECK(esp_wifi_connect());
            break;
        default:
            break;
    }
    return ESP_OK;
}

/* Initialize Wi-Fi as sta and set scan method */
static void wifi_scan(void)
{
    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_APSTA) );
    wifi_config_t sta_config = {
        .sta = {
            .ssid = "HUAWEI P20",
            .password = "wjwjljlj",
            .bssid_set = false
        },
    };
	wifi_config_t ap_config = {
        .ap = {
            .ssid = "esp32",
            .password = "dinagroup",
            .ssid_len = 0,
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA_PSK
        }
    };
	
	
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));
    esp_err_t tmp =  esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    ESP_ERROR_CHECK(esp_wifi_start());
	
}



void app_main()
{
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK( ret );

    wifi_scan();
}
