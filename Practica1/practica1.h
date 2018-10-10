#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>

#define ETH_FRAME_MAX 1514 /*Tamanio maximo eth*/
#define TAM_CADENA 256     /*Tamanio maximo nombre del pcap*/

void captura(int sennal);

void callback_live(uint8_t *nbytes, const struct pcap_pkthdr* cabecera, const uint8_t* paquete);

void callback_offline(uint8_t *nbytes, const struct pcap_pkthdr* cabecera, const uint8_t* paquete);


