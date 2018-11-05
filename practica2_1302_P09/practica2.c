/**
* Practica 2 Redes de Comunicación
* Archivo practica2.c
* Autores : Lucía Rivas Molina <lucia.rivasmolina@estudiante.uam.es>
*           Daniel Santo-Tomás López <daniel.santo-tomas@estudiante.uam.es>
*/
#include "practica2.h"

/*Variables Globales*/
pcap_t *descr = NULL;
uint64_t contador = 0;
uint8_t ipsrc_filter[IP_ALEN] = {NO_FILTER}; /*Ip origen*/
uint8_t ipdst_filter[IP_ALEN] = {NO_FILTER}; /*Ip destino*/
uint16_t sport_filter= NO_FILTER;            /*Puerto origen*/
uint16_t dport_filter = NO_FILTER;           /*Puerto destino*/

/**
* Handle de la sennal SIGINT
*/
void handleSignal(int nsignal)
{
	(void) nsignal;
	printf("Control C pulsado\n");
	pcap_breakloop(descr);
}

/**
* Main de la practica
*/
int main(int argc, char **argv)
{

	char errbuf[PCAP_ERRBUF_SIZE];

	int long_index = 0, retorno = 0;
	char opt;

	if (signal(SIGINT, handleSignal) == SIG_ERR) {
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}

	if (argc == 1) {
		printf("Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]\n", argv[0]);
		exit(ERROR);
	}

	static struct option options[] = {
		{"f", required_argument, 0, 'f'},
		{"i",required_argument, 0,'i'},
		{"ipo", required_argument, 0, '1'},
		{"ipd", required_argument, 0, '2'},
		{"po", required_argument, 0, '3'},
		{"pd", required_argument, 0, '4'},
		{"h", no_argument, 0, '5'},
		{0, 0, 0, 0}
	};

	/*Tomamos los argumentos*/
	while ((opt = getopt_long_only(argc, argv, "f:i:1:2:3:4:5", options, &long_index)) != -1) {
		switch (opt) {
		/*Pasamos la interfaz*/
		case 'i' :
			if(descr) { /* comprobamos que no se ha abierto ninguna otra interfaz o fichero*/
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}

			if ((descr = pcap_open_live(optarg, 5, 0, 100, errbuf)) == NULL) {
				perror(errbuf);
				exit(ERROR);
			}
			break;

		/*Pasamos el pcap*/
		case 'f' :
			if(descr) {
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}

			if ((descr = pcap_open_offline(optarg, errbuf)) == NULL) {
				perror(errbuf);
				exit(ERROR);
			}

			break;

		case '1' :
			if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipsrc_filter[0]), &(ipsrc_filter[1]), &(ipsrc_filter[2]), &(ipsrc_filter[3])) != IP_ALEN) {
				printf("Error ipo_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '2' :
			if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipdst_filter[0]), &(ipdst_filter[1]), &(ipdst_filter[2]), &(ipdst_filter[3])) != IP_ALEN) {
				printf("Error ipd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '3' :
			if ((sport_filter= atoi(optarg)) == 0) {
				printf("Error po_filtro.Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '4' :
			if ((dport_filter = atoi(optarg)) == 0) {
				printf("Error pd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '5' :
			printf("Ayuda. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
			exit(ERROR);
			break;

		case '?' :
		default:
			printf("Error. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
			exit(ERROR);
			break;
		}
	}

	if (!descr) {
		printf("No selecciono ningún origen de paquetes.\n");
		return ERROR;
	}

	/*Simple comprobacion de la correcion de la lectura de parametros*/
	printf("Filtro:");
	if(ipsrc_filter[0] != NO_FILTER){
		printf("ipsrc_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipsrc_filter[0], ipsrc_filter[1], ipsrc_filter[2], ipsrc_filter[3]);
  }
  if(ipdst_filter[0] != NO_FILTER){
		printf("ipdst_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipdst_filter[0], ipdst_filter[1], ipdst_filter[2], ipdst_filter[3]);
	}
	if (sport_filter != NO_FILTER) {
		printf("po_filtro=%"PRIu16"\t", sport_filter);
	}

	if (dport_filter != NO_FILTER) {
		printf("pd_filtro=%"PRIu16"\t", dport_filter);
	}

	printf("\n\n");

	retorno = pcap_loop(descr, NO_LIMIT, analizar_paquete, NULL);
	switch(retorno)	{
		case OK:
			printf("Traza leída\n");
			break;
		case PACK_ERR:
			printf("Error leyendo paquetes\n");
			break;
		case BREAKLOOP:
			printf("pcap_breakloop llamado\n");
			break;
	}
	printf("Se procesaron %"PRIu64" paquetes.\n\n", contador);
	pcap_close(descr);
	return OK;
}



void analizar_paquete(u_char *user,const struct pcap_pkthdr *hdr, const uint8_t *pack)
{
	(void)user;
	printf("Nuevo paquete capturado el %s\n", ctime((const time_t *) & (hdr->ts.tv_sec)));
	contador++;
	int i = 0, desp, protocolo, tam_ip;
	const uint8_t tipo_eth[2] = {8, 0};
	int ip_longitud[2] = {0, 0};
	int puerto[2] = {0, 0};
	int offset[2] = {0, 0};

	/*Imprimimos la cabecera ethernet*/
	printf("Direccion ETH destino = ");
	printf("%02X", pack[0]);

	for (i = 1; i < ETH_ALEN; i++) {
		printf("-%02X", pack[i]);
	}

	printf("\n");
	pack += ETH_ALEN;

	printf("Direccion ETH origen = ");
	printf("%02X", pack[0]);

	for (i = 1; i < ETH_ALEN; i++) {
		printf("-%02X", pack[i]);
	}

	printf("\n");

	pack += ETH_ALEN;

	printf("TIPO ETHERNET = ");
	for (i = 0; i < ETH_TLEN; i++) {
		printf("%02X", pack[i]);
	}
	printf("\n");
	/*Comprobamos que el protocolo es el IPv4*/
	for(i = 0; i < ETH_TLEN; i++) {
		if(pack[i] != tipo_eth[i]){
			printf("No es el protocolo esperado\n\n");
			return;
		}
	}

	pack += ETH_TLEN;

	/*Imprimimos la cabecera IP*/
	printf("VERSION IP = ");
	printf("%d", (pack[0]&(0xF0)) >> 4);
	printf("\n");
	printf("TAMAÑO CABECERA = ");
	printf("%d", (pack[0]&(0x0F))*4); /*Por 4 palabras por fila*/
	tam_ip = (pack[0]&(0x0F));
	printf("\n");

	pack += 2;

	printf("LONGITUD TOTAL = ");
	for(i = 0; i < 2; i++){
		ip_longitud[i] = pack[i];
	}
	printf("%d\n", (ip_longitud[0] << 8) + ip_longitud[1]);

	pack += 4;
	printf("DESPLAZAMIENTO = ");
	for(i = 0; i < 2; i++){
		offset[i] = pack[i];
	}
	desp = (((offset[0] & 0x1) << 8) + (offset[1]));
	printf("%d\n", desp*8);

	pack += 2;
	printf("TIEMPO DE VIDA = ");
	printf("%d\n", pack[0]);

	pack += 1;
	printf("PROTOCOLO = ");
	printf("%d\n", pack[0]);
	protocolo = pack[0];

	pack += 3;
	printf("DIRECCION ORIGEN =");
	printf(" %d", pack[0]);
	for(i = 1; i < 4; i++){
		printf(".%d", pack[i]);
	}
	printf("\n");

	/*Comprobamos que la ip origen es la del filtro*/
	if(ipsrc_filter[0] != NO_FILTER){
			for(i = 0; i < 4; i++){
				if(ipsrc_filter[i] != pack[i]){
					printf("No se cumple el filtro IPO\n\n");
					return;
				}
			}
	}

	pack += 4;
	printf("DIRECCION DESTINO =");
	printf(" %d", pack[0]);
	for(i = 1; i < 4; i++){
		printf(".%d", pack[i]);
	}
	printf("\n");

	/*Comprobamos que la ip destino es la del filtro*/
	if(ipdst_filter[0] != NO_FILTER){
			for(i = 0; i < 4; i++){
				if(ipdst_filter[i] != pack[i]){
					printf("No se cumple el filtro IPD\n\n");
					return;
				}
			}
	}

	/*Comprobamos que sea distinto de 0*/
	if(desp != 0){
		printf("El desplazamiento no es 0\n\n");
		return;
	}
	/*Comprobamos que el protocolo sea UDP o TCP*/
	if(protocolo != 6 && protocolo != 17){
		printf("El protocolo no es UDP ni TCP\n\n");
		return;
	}
	/*Si ihl es mayor que 5 hay que sumar 4 bytes mas por el campo opciones*/
	if(tam_ip > 5){
		pack += 8;
	}
	else{
		pack += 4;
	}

	/*Imprimimos la cabecera TCP*/
	if(protocolo == 6){
		printf("PUERTO ORIGEN = ");;
		for(i = 0; i < 2; i++){
			puerto[i] = pack[i];
		}
		printf("%d\n", (puerto[0] << 8) + puerto[1]);
		/*Comprobamos que el filtro puerto origen se cumple*/
		if(sport_filter != NO_FILTER && ((puerto[0] << 8) + puerto[1]) != sport_filter){
			printf("No se cumple el filtro PO\n\n");
			return;
		}

		pack += 2;
		printf("PUERTO DESTINO = ");;
		for(i = 0; i < 2; i++){
			puerto[i] = pack[i];
		}
		printf("%d\n", (puerto[0] << 8) + puerto[1]);
		/*Comprobamos que el filtro puerto destino se cumple*/
		if(dport_filter != NO_FILTER && ((puerto[0] << 8) + puerto[1]) != dport_filter){
			printf("No se cumple el filtro PD\n\n");
			return;
		}

		pack += 11;
		printf("SYN = %d\n", pack[0]&0x02 >> 1);
		printf("FYN = %d\n", pack[0]&0x01);
	}

	/*Impimimos la cabecera UDP*/
	else if(protocolo == 17){
		printf("PUERTO ORIGEN = ");;
		for(i = 0; i < 2; i++){
			puerto[i] = pack[i];
		}
		printf("%d\n", (puerto[0] << 8) + puerto[1]);
		/*Comprobamos que el filtro puerto origen se cumple*/
		if(sport_filter != NO_FILTER && ((puerto[0] << 8) + puerto[1]) != sport_filter){
			printf("No se cumple el filtro PO\n\n");
			return;
		}

		pack += 2;
		printf("PUERTO DESTINO = ");;
		for(i = 0; i < 2; i++){
			puerto[i] = pack[i];
		}
		printf("%d\n", (puerto[0] << 8) + puerto[1]);
		/*Comprobamos que el filtro puerto destino se cumple*/
		if(dport_filter != NO_FILTER && ((puerto[0] << 8) + puerto[1]) != dport_filter){
			printf("No se cumple el filtro PD\n\n");
			return;
		}

		pack += 2;
		printf("LONGITUD = ");;
		for(i = 0; i < 2; i++){
			puerto[i] = pack[i];
		}
		printf("%d\n", (puerto[0] << 8) + puerto[1]);
	}

	printf("\n\n");

}
