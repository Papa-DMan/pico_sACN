#include <FreeRTOS.h>
#include <queue.h>
#include <stdio.h>
#include <task.h>

#include "lwip/ip4_addr.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"
#include "piodmx.h"
#include "sACNdefs.h"
#include "hardware/timer.h"
#include "pico/util/datetime.h"
#include <time.h>
#include "lwip/tcpip.h"
#include "lwip/api.h"
#include "lwip/opt.h"
#include <utility>
#include <vector>
#include <array>
#include <map>
#include "lwip/apps/fs.h"
#include "fsdata.h"
#include "core_json.h"
#include <cstring>
#include <set>

#define NUMDMX 1

#define SSID "TestAP"
#define PASSWORD "12345678"

static QueueHandle_t udpQueue = NULL;
static QueueHandle_t tcpQueue = NULL;
static std::map<uint16_t, QueueHandle_t> UniverseQueues;
static uint8_t ACNPacketIdentifier[12] = {0x41, 0x53, 0x43, 0x2d, 0x45, 0x31, 0x2e, 0x31, 0x37, 0x00, 0x00, 0x00};
static uint8_t Vector_Root_E131_Data[4] = {0x00, 0x00, 0x00, 0x04};
static uint8_t Vector_Root_E131_Extended[4] = {0x00, 0x00, 0x00, 0x01};
static std::array<DMX*, NUMDMX + 1> dmx_registry;

void udp_cb_func(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    if (p->len < 37) {                                  //if the packet is less than 37 bytes, it is not a valid ACN packet
        pbuf_free(p);
        return;
    }                  
    if (p->len >= 37) {                                 //if the packet is at least 37 bytes, validate the ACN root layer
        ACNRootLayer *root = (ACNRootLayer* )p->payload;
        if (!validRoot(root)) {
            pbuf_free(p);
            return;
        }
    }
    if (p->len >= 43) {                                 //if the packet is at least 43 bytes, validate the ACN framing layer vector
        uint8_t *framing_vector = (uint8_t* )p->payload + 39;
        if (framing_vector[0] == framing_vector[1] && framing_vector[1] == framing_vector[2] && framing_vector[42] != 0x02) {
            pbuf_free(p);
            return;
        }
    }
    ACNDataPacket data;
    memcpy(&data, p->payload, p->len);
    pbuf_free(p);
    xQueueSend(udpQueue, &data, portMAX_DELAY);
}

void dmx_loop(void *pvParameters) {
    TickType_t xLastWakeTime = xTaskGetTickCount();
    while (1) {
        vTaskDelayUntil(&xLastWakeTime, pdMS_TO_TICKS(16));
        for (auto d : dmx_registry) {
            if (d == nullptr) {
                continue;
            }
            if (d->busy()) {
                continue;
            }
            d->sendDMX();
        }
    }
}



void universe_task(void *pvParameters) {
    uint8_t* sc = static_cast<uint8_t*>(pvParameters);                              //get the universe number from the parameter
    uint16_t queueNum = *sc;
    DMX *dmx = new DMX((queueNum > 4)? pio1 : pio0 );
    dmx_registry.at(queueNum) = dmx;
    ACNDataPacket udpData;
    uint8_t dmxData[513];
    dmx->begin(5, 6);
    while (true) {
        if (xQueueReceive(UniverseQueues[queueNum], &udpData, portMAX_DELAY) == pdPASS) {
            memcpy(&dmxData, udpData.dmpLayer.propertyValues, 513);
            while (dmx->busy()) {
                vTaskDelay(1);
            }
            dmx->unsafeWriteBuffer((uint8_t*)&dmxData, false);
        }
    }
}



void listen_task(void *pvParameters) {
    netconn* conn = (netconn*)pvParameters;                             //get the UDP socket from the parameter
    ip_addr_t multicast_addr;
    for (int i = 1; i < 2; i++) {
        xTaskCreate(universe_task, "Universe", 1024, &i, 1, NULL);      //spawn the universe tasks
        IP_ADDR4(&multicast_addr, 239, 255, 0, i);                      //set the multicast address
        netconn_join_leave_group(conn, &multicast_addr, IP_ADDR_ANY, NETCONN_JOIN);  //join the multicast group
    }
    xTaskCreate(dmx_loop, "DMX Loop", 512, NULL, 3, NULL);              //spawn the DMX loop task

    udp_recv(conn->pcb.udp, udp_cb_func, NULL);                         //set the callback function for the UDP socket
    ACNDataPacket udpData;                                              //create a buffer to hold the UDP data
    while (true) {
        if (xQueueReceive(udpQueue, &udpData, portMAX_DELAY) == pdPASS) {   //wait for a UDP packet
            uint16_t universe = (udpData.framingLayer.universe[0] << 8) | udpData.framingLayer.universe[1];  //get the universe number from the packet
            //printf("Packet for universe %d\n", universe);
            if (UniverseQueues.find(universe) == UniverseQueues.end()) {  //if the universe is not in the map, create a queue for it
                //printf("Not a Universe we care about\n");
                break;
            }
            xQueueSend(UniverseQueues[universe], &udpData, portMAX_DELAY);  //send the packet to the appropriate universe task
        }
    }
}

bool validPacket(netbuf * buf) {
    uint8_t *payload;
    uint16_t len;

    netbuf_data(buf, (void**)&payload, &len);

    if (len < 37) {                                  //if the packet is less than 37 bytes, it is not a valid ACN packet
        return false;
    }                  
    if (len >= 37) {                                 //if the packet is at least 37 bytes, validate the ACN root layer
        ACNRootLayer *root = (ACNRootLayer* )payload;
        if (!validRoot(root)) {
            return false;
        }
    }
    if (len >= 43) {                                 //if the packet is at least 43 bytes, validate the ACN framing layer vector
        uint8_t *framing_vector = (uint8_t* )payload + 39;
        if (framing_vector[0] == framing_vector[1] && framing_vector[1] == framing_vector[2] && framing_vector[42] != 0x02) {
            return false;
        }
    }
    return true;
}



void newlisten_task(void* pvParameters) {
    netconn* conn= (netconn*)pvParameters;
    ip_addr_t multicast_addr;
    for (int i = 1; i < 2; i++) {
        xTaskCreate(universe_task, "Universe", 1024, &i, 1, NULL);
        IP_ADDR4(&multicast_addr, 239, 255, 0, i);
        netconn_join_leave_group(conn, &multicast_addr, IP_ADDR_ANY, NETCONN_JOIN);
    }
    xTaskCreate(dmx_loop, "DMX Loop", 512, NULL, 3, NULL);

    while(true) {
        struct netbuf* buf;
        err_t err = netconn_recv(conn, &buf);
        if (err == ERR_OK) {
            if(validPacket(buf)) {
                uint8_t *payload;
                uint16_t len;
                netbuf_data(buf, (void**)&payload, &len);
                ACNDataPacket udpData;
                memcpy(&udpData, payload, len);
                uint16_t universe = (udpData.framingLayer.universe[0] << 8) | udpData.framingLayer.universe[1];
                if (UniverseQueues.find(universe) == UniverseQueues.end()) {
                    break;
                }
                xQueueSend(UniverseQueues[universe], &udpData, portMAX_DELAY);
            }
            netbuf_free(buf);
        }
    }
}



void wifi_init_task(void *) {
    if (cyw43_arch_init_with_country(CYW43_COUNTRY_USA)) {                  //init wifi module with country code
        //printf("CYW43 initalization failed\n");
    }

    cyw43_arch_enable_sta_mode();                                           //enable station mode
    cyw43_wifi_pm(&cyw43_state, CYW43_NO_POWERSAVE_MODE);                   //disable powersave mode
    netif_default->hostname = "rfu";                                        //set hostname to rfu

    //printf("Connecting to Wi-Fi...\n");                                     //connect to wifi asychronously and wait for connection
    cyw43_arch_wifi_connect_async(SSID, PASSWORD, CYW43_AUTH_WPA2_AES_PSK);
    while(cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA) < 3) {
        vTaskDelay(1);
    }

    //printf("Connected to Wi-Fi\n");                                         //log it
    //printf("IP Address: %s\n", ip4addr_ntoa(&netif_default->ip_addr));

    netif_default->flags |= NETIF_FLAG_IGMP;                                //enable IGMP

    netconn * igmp = netconn_new(NETCONN_UDP);                              //create UDP socket
    netconn_set_recvtimeout(igmp, 0);                                       //set timeout to 0

    netconn_bind(igmp, IP_ADDR_ANY, 5568);                                  //bind to our multicast application port

    xTaskCreate(listen_task, "IGMP", 1024, igmp, 2, NULL);                  //create task to listen for IGMP packets

    vTaskDelete(NULL);
}



int main() {
    stdio_init_all();
    timer_hw->dbgpause = 0;

    //dmxQueue = xQueueCreate(5, sizeof(uint8_t[513]));
    for (int i = 1; i <= NUMDMX; i++) {
        UniverseQueues.emplace(i, xQueueCreate(5, sizeof(ACNDataPacket)));
    }
    udpQueue = xQueueCreate(30, sizeof(ACNDataPacket));
    

    

    xTaskCreate(wifi_init_task, "wifi_init_task", 1024, NULL, 1, NULL);
    vTaskStartScheduler();
}