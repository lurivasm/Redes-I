/***************************************************************************
 practica3.c
 Inicio, funciones auxiliares y modulos de transmision implmentados y a implementar de la practica 4.
Compila con warning pues falta usar variables y modificar funciones

 Compila: make
 Autor: Jose Luis Garcia Dorado, Jorge E. Lopez de Vergara Mendez
 2018 EPS-UAM v1
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "interface.h"
#include "practica3.h"

/***************************Variables globales utiles*************************************************/
pcap_t *descr, *descr2; /*Descriptores de la interface de red*/
pcap_dumper_t * pdumper;/*y salida a pcap*/
uint64_t cont = 0;	/*Contador numero de mensajes enviados*/
char interface[10];	/*Interface donde transmitir por ejemplo "eth0"*/
uint16_t ID = 1;		/*Identificador IP*/
char flag_mostrar = 0;  /*Flag para mostrar los datos en hexadecimal*/


void handleSignal(int nsignal){
	printf("Control C pulsado (%"PRIu64")\n", cont);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv){

	char errbuf[PCAP_ERRBUF_SIZE];
	char fichero_pcap_destino[CADENAS];
	uint8_t IP_destino_red[IP_ALEN];
	uint16_t MTU;
	uint16_t datalink;
	uint16_t puerto_destino;
	char data[IP_DATAGRAM_MAX];
	uint16_t pila_protocolos[CADENAS];


	int long_index = 0;
	char opt;
	char flag_iface = 0, flag_ip = 0, flag_port = 0, flag_file = 0, flag_dontfrag = 0;
	FILE *file = NULL;

	static struct option options[] = {
		{"if",required_argument,0,'1'},
		{"ip",required_argument,0,'2'},
		{"pd",required_argument,0,'3'},
		{"f",required_argument,0,'4'},
		{"d",no_argument,0,'5'},
		{"m",no_argument,0,'6'},
		{"h",no_argument,0,'7'},
		{0,0,0,0}
	};

		/*Dos opciones: leer de stdin o de fichero, adicionalmente para pruebas si no se
		  introduce argumento se considera que el mensaje es "Payload "*/
	while ((opt = getopt_long_only(argc, argv,"1:2:3:4:5:6:7", options, &long_index )) != -1) {
		switch (opt) {

			case '1' :

				flag_iface = 1;
				/*Por comodidad definimos interface como una variable global*/
				sprintf(interface,"%s",optarg);
				break;

			case '2' :

				flag_ip = 1;
				/*Leemos la IP a donde transmitir y la almacenamos en orden de red*/
				if (sscanf(optarg,"%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",
				                   &(IP_destino_red[0]),&(IP_destino_red[1]),&(IP_destino_red[2]),&(IP_destino_red[3])) != IP_ALEN){
					printf("Error: Fallo en la lectura IP destino %s\n", optarg);
					exit(ERROR);
				}

				break;

			case '3' :

				flag_port = 1;
				/*Leemos el puerto a donde transmitir y la almacenamos en orden de hardware*/
				puerto_destino = atoi(optarg);
				break;

			case '4' :

				if(strcmp(optarg,"stdin") == 0) {
					if (fgets(data, sizeof data, stdin)== NULL) {
						printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					/*Comprobamos que sea par*/
					if (strlen(data)%2 != 0){
						sprintf(data, "%s", " ");
					}
					sprintf(fichero_pcap_destino,"%s%s","stdin",".pcap");
				}
				else {
					sprintf(fichero_pcap_destino,"%s%s",optarg,".pcap");
					if((file = fopen(optarg, "r")) == NULL){
						printf("Error abriendo fichero %s\n", optarg);
						return ERROR;
					}
					fread(data, sizeof data, 1, file);
					
					/*Comprobamos que sea par*/
					if (strlen(data)%2 != 0){
						sprintf(data, "%s", " ");
					}
					fclose(file);
				}
				flag_file = 1;
				break;

			case '5' :
				flag_dontfrag = 1; /* El usuario solicita que los paquetes se envien con el bit DF=1.*/
				break;

			case '6' :
				flag_mostrar = 1; /* El usuario solicita que se muestren en hexadecimal las tramas enviadas.*/
				break;

			case '7' : printf("Ayuda. Ejecucion: %s -if interface -ip direccion_IP -pd puerto [-f /ruta/fichero_a_transmitir o stdin] [-d] [-m]: %d\n",argv[0],argc); exit(ERROR);
				break;

			case '?' :
			default: printf("Error. Ejecucion: %s -if interface -ip direccion_IP -pd puerto [-f /ruta/fichero_a_transmitir o stdin] [-d] [-m]: %d\n",argv[0],argc); exit(ERROR);
				break;
        }
    }

	if ((flag_iface == 0) || (flag_ip == 0) || (flag_port == 0)){
		printf("Error. Ejecucion: %s -if interface -ip direccion_IP -pd puerto [-f /ruta/fichero_a_transmitir o stdin] [-d] [-m]: %d\n",argv[0], argc);
		exit(ERROR);
	}

	else {
		printf("Interface:\n\t%s\n", interface);
		printf("IP:\n\t%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n", IP_destino_red[0], IP_destino_red[1], IP_destino_red[2], IP_destino_red[3]);
		printf("Puerto destino:\n\t%"PRIu16"\n", puerto_destino);
		if (flag_dontfrag) printf("Se solicita enviar paquete con bit DF = 1\n");
		if (flag_mostrar) printf("Se solicita mostrar las tramas enviadas en hexadecimal\n");
	}

	if (flag_file == 0) {
		sprintf(data,"%s","Payload "); /*Deben ser pares!*/
		sprintf(fichero_pcap_destino,"%s%s","debugging",".pcap");
	}

	if(signal(SIGINT, handleSignal) == SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		return ERROR;
	}

	/*Inicializamos las tablas de protocolos*/
	if(inicializarPilaEnviar() == ERROR){
      	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}

	/*Leemos el tamano maximo de transmision del nivel de enlace*/
	if(obtenerMTUInterface(interface, &MTU) == ERROR)	return ERROR;

	/*Descriptor de la interface de red donde inyectar trafico*/
	if ((descr = pcap_open_live(interface, MTU + ETH_HLEN, 0, 0, errbuf)) == NULL){
		printf("Error: pcap_open_live(): %s %s %d.\n", errbuf, __FILE__, __LINE__);
		return ERROR;
	}

	datalink = (uint16_t)pcap_datalink(descr); /*DLT_EN10MB==Ethernet*/

	/*Descriptor del fichero de salida pcap para debugging*/
	descr2 = pcap_open_dead(datalink, MTU+ETH_HLEN);
	pdumper = pcap_dump_open(descr2, fichero_pcap_destino);

	/*Formamos y enviamos el trafico, debe enviarse un unico segmento
	  por llamada a enviar() aunque luego se traduzca en mas de un datagrama
	  Primero, un paquete ICMP; en concreto, un ping*/
	pila_protocolos[0] = ICMP_PROTO;
	pila_protocolos[1] = IP_PROTO;
	pila_protocolos[2] = 0;

	Parametros parametros_icmp;
	parametros_icmp.tipo = PING_TIPO;
	parametros_icmp.codigo = PING_CODE;
	parametros_icmp.bit_DF = flag_dontfrag;
	memcpy(parametros_icmp.IP_destino, IP_destino_red, IP_ALEN);

	if(enviar((uint8_t*)ICMP_DATA, strlen(ICMP_DATA), pila_protocolos, &parametros_icmp) == ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;
	printf("Enviado mensaje %"PRIu64", ICMP almacenado en %s\n\n", cont,fichero_pcap_destino);


	/*Luego, un paquete UDP
	  Definimos la pila de protocolos que queremos seguir*/
	pila_protocolos[0] = UDP_PROTO;
	pila_protocolos[1] = IP_PROTO;
	pila_protocolos[2] = ETH_PROTO;

	/*Rellenamos los parametros necesario para enviar el paquete a su destinatario y proceso*/
	Parametros parametros_udp;
	memcpy(parametros_udp.IP_destino, IP_destino_red,IP_ALEN);
	parametros_udp.bit_DF = flag_dontfrag;
	parametros_udp.puerto_destino = puerto_destino;

  /*Aumentamos el identificador ip*/
	ID++;

	/*Enviamos*/
	if(enviar((uint8_t*)data, strlen(data), pila_protocolos, &parametros_udp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else cont++;

	printf("Enviado mensaje %"PRIu64", almacenado en %s\n\n\n", cont,fichero_pcap_destino);

	/*Cerramos descriptores*/
	pcap_close(descr);
	pcap_dump_close(pdumper);
	pcap_close(descr2);
	return OK;
}


/****************************************************************************************
 * Nombre: enviar                                                                       *
 * Descripcion: Esta funcion envia un mensaje                                           *
 * Argumentos:                                                                          *
 *  -mensaje: mensaje a enviar                                                          *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -longitud: bytes que componen mensaje                                               *
 *  -parametros: parametros necesario para el envio (struct parametros)                 *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t enviar(uint8_t* mensaje, uint32_t longitud, uint16_t* pila_protocolos, void *parametros){
	uint16_t protocolo = pila_protocolos[0];
	printf("Enviar(%"PRIu16") %s %d.\n", protocolo, __FILE__, __LINE__);

	if(protocolos_registrados[protocolo] == NULL){
		printf("Protocolo %"PRIu16" desconocido\n", protocolo);
		return ERROR;
	}
	else {
		return protocolos_registrados[protocolo](mensaje, longitud, pila_protocolos, parametros);
	}
	return ERROR;
}


/*************************** Pila de protocolos a implementar************************************/


/****************************************************************************************
 * Nombre: moduloICMP                                                                   *
 * Descripcion: Esta funcion implementa el modulo de envio ICMP                         *
 * Argumentos:                                                                          *
 *  -mensaje: mensaje a anadir a la cabecera ICMP                                       *
 *  -longitud: bytes que componen el mensaje                                            *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t moduloICMP(uint8_t* mensaje, uint32_t longitud, uint16_t* pila_protocolos, void *parametros){
	uint8_t segmento[ICMP_DATAGRAM_MAX] = {0};
	uint8_t aux8;
	uint8_t auxchecksum[2];
	uint16_t aux16;
	uint32_t pos = 0, checksum = 0;
	uint8_t protocolo_inferior = pila_protocolos[1];


	printf("modulo ICMP(%"PRIu16") %s %d.\n", protocolo_inferior, __FILE__, __LINE__);

	/*Tipo y Código*/
	aux8 = PING_TIPO;
	memcpy(segmento + pos, &aux8, sizeof(uint8_t));
	pos = sizeof(uint8_t);

	aux8 = PING_CODE;
	memcpy(segmento + pos, &aux8, sizeof(uint8_t));
	pos += sizeof(uint8_t);

	/*Puntero al checksum*/
	checksum = pos;
	pos += sizeof(uint16_t);

	/*Identificador*/
	aux16 = getpid();
	aux16 = htons(aux16);
	memcpy(segmento + pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	/*Número de secuencia*/
	aux16 = htons(1);
	memcpy(segmento + pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	/*Datos*/
	if(longitud < (ICMP_DATAGRAM_MAX - ICMP_HLEN)){
		memcpy(segmento + pos, mensaje, longitud);
	}
	else{ /*Truncamos el mensaje*/
		memcpy(segmento + pos, mensaje, ICMP_DATAGRAM_MAX - ICMP_HLEN);
	}
	pos += longitud;

	/*Checksum*/
	calcularChecksum(segmento, pos, auxchecksum);
	memcpy(segmento + checksum, auxchecksum, sizeof(uint16_t));

	/*Se llama al protocolo definido de nivel inferior a traves de los punteros
	 registrados en la tabla de protocolos registrados*/
	return protocolos_registrados[protocolo_inferior](segmento, pos, pila_protocolos, parametros);
}


/****************************************************************************************
 * Nombre: moduloUDP                                                                    *
 * Descripcion: Esta funcion implementa el modulo de envio UDP                          *
 * Argumentos:                                                                          *
 *  -mensaje: mensaje a enviar                                                          *
 *  -longitud: bytes que componen mensaje                                               *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t moduloUDP(uint8_t* mensaje, uint32_t longitud, uint16_t* pila_protocolos, void *parametros){
	uint8_t segmento[UDP_SEG_MAX] = {0};
	uint16_t puerto_origen = 0, aux16;
	uint32_t pos = 0;
	uint8_t protocolo_inferior = pila_protocolos[1];

	printf("modulo UDP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	if (longitud > UDP_SEG_MAX){
		printf("Error: mensaje demasiado grande para UDP (%d).\n",UDP_SEG_MAX);
		return ERROR;
	}

	Parametros udpdatos= *((Parametros*)parametros);
	uint16_t puerto_destino = udpdatos.puerto_destino;

	/*Obtenemos el puerto origen*/
	if (obtenerPuertoOrigen(&puerto_origen) == ERROR){
		printf("Error obtenerPuertoOrigen %d\n\n", __LINE__);
		return ERROR;
	}

	aux16 = htons(puerto_origen);
	memcpy(segmento + pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	/*Puerto Destino*/
	aux16 = htons(puerto_destino);
	memcpy(segmento + pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	/*Longitud*/
	aux16 = htons(longitud + UDP_HLEN);
	memcpy(segmento + pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	/*Checksum a 0*/
	aux16 = 0;
	memcpy(segmento + pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	/*Mensaje*/
	memcpy(segmento + pos, mensaje, longitud);

	return protocolos_registrados[protocolo_inferior](segmento, longitud + pos, pila_protocolos, parametros);
}


/****************************************************************************************
 * Nombre: moduloIP                                                                     *
 * Descripcion: Esta funcion implementa el modulo de envio IP                           *
 * Argumentos:                                                                          *
 *  -segmento: segmento a enviar                                                        *
 *  -longitud: bytes que componen el segmento                                           *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t moduloIP(uint8_t* segmento, uint32_t longitud, uint16_t* pila_protocolos, void *parametros){
	uint8_t datagrama[IP_DATAGRAM_MAX] = {0};
	uint16_t aux16, flags, long_data, mtu;
	uint64_t longitud_paquete;
	uint8_t aux8;
	uint32_t pos = 0, pos_offset = 0, pos_checksum = 0, pos_len = 0;
	uint8_t IP_origen[IP_ALEN];
	uint16_t protocolo_superior = pila_protocolos[0];
	uint8_t protocolo_inferior = pila_protocolos[2];
	pila_protocolos++;
	
	int i, num_frag;
	
	uint8_t mascara[IP_ALEN], IP_rango_origen[IP_ALEN], IP_rango_destino[IP_ALEN], gateway[IP_ALEN];
	uint8_t auxchecksum[2];

	printf("modulo IP(%"PRIu16") %s %d.\n", protocolo_inferior, __FILE__, __LINE__);

	Parametros ipdatos = *((Parametros*)parametros);
	uint8_t* IP_destino = ipdatos.IP_destino;
	
	/*Obtenemos mtu*/
	if(obtenerMTUInterface(interface, &mtu) == ERROR) return ERROR;

	/*Obtenemos la ip origen*/
	if(obtenerIPInterface(interface, IP_origen) == ERROR){
		printf("Error obtenerIPInterface %d\n", __LINE__);
		return ERROR;
	}

	/*Obtenemos la máscara*/
	if(obtenerMascaraInterface(interface, mascara) == ERROR){
		printf("Error obtenerMascaraInterface %d\n", __LINE__);
		return ERROR;
	}

	/*Aplicamos mascaras a la ip origen y destino y las comparamos*/
	if(aplicarMascara(IP_origen, mascara, IP_ALEN, IP_rango_origen) == ERROR){
		printf("Error aplicarMascara origen %d\n", __LINE__);
		return ERROR;
	}

	if(aplicarMascara(IP_destino, mascara, IP_ALEN, IP_rango_destino) == ERROR){
		printf("Error aplicarMascara origen %d\n", __LINE__);
		return ERROR;
	}

	if (memcmp(IP_rango_destino, IP_rango_origen, IP_ALEN) == 0) {

		/*Solicitud ARP*/
		if(solicitudARP(interface, IP_destino, ipdatos.ETH_destino) == ERROR) {
			printf("Error Solicitud ARP\n");
			return ERROR;
		}
	}
	/*Solicitamos gateway*/
	else{
		if (obtenerGateway(interface, gateway) == ERROR){
			printf("Error obtenerGatway %d", __LINE__);
			return ERROR;
		}
		if(solicitudARP(interface, gateway, ipdatos.ETH_destino) == ERROR) {
			printf("Error Solicitud ARP\n");
			return ERROR;
		}
	}
	
	/*Versión IP y IHL*/
	aux8 = 0x45;
	memcpy(datagrama, &aux8, sizeof(uint8_t));
	pos = sizeof(uint8_t);

	/*Tipo de Servicio a 0*/
	pos += sizeof(uint8_t);

    /*Longitud total*/
	pos_len = pos;
	pos += sizeof(uint16_t);

	/*Identifcación*/
	aux16 = htons((uint16_t)ID);
	memcpy(datagrama + pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	/*Flags y offset*/
	pos_offset = pos;
	pos += sizeof(uint16_t);

	/*Tiempo de vida*/
	aux8 = 128;
	memcpy(datagrama + pos, &aux8, sizeof(uint8_t));
	pos += sizeof(uint8_t);

	/*Protocolo*/
	aux8 = (uint8_t) protocolo_superior;
	memcpy(datagrama + pos, &aux8, sizeof(uint8_t));
	pos += sizeof(uint8_t);

	/*Checksum al final*/
	pos_checksum = pos;
	pos += sizeof(uint16_t);

	/*Direccion origen y destino*/
	memcpy(datagrama + pos, IP_origen, IP_ALEN);
	pos += IP_ALEN;
	memcpy(datagrama + pos, IP_destino, IP_ALEN);
	pos += IP_ALEN;


	long_data = mtu - IP_HLEN;
	num_frag = ceil(longitud / (1.0*long_data));

	/*Fragmentacion*/
	if(ipdatos.bit_DF == 0){

		for(i = 0; i < num_frag; i++){

			if(i == num_frag - 1){ /*Último frgamento*/
				flags = 0x0000;
				longitud_paquete = longitud - i*long_data;
			}
			/*Resto de casos*/
			else{
				flags = 0x2000;
				longitud_paquete = long_data;
			}

			/*Longitud Total*/
			aux16 = htons(longitud_paquete + IP_HLEN);
			memcpy(datagrama + pos_len, &aux16, sizeof(uint16_t));

			/*Flags y offset (multiplo de 8B)*/
			aux16 = htons(flags | (i*(long_data >> 3)));
			memcpy(datagrama + pos_offset, &aux16, sizeof(uint16_t));

			/*Checksum*/
			memset(datagrama + pos_checksum, 0, sizeof(uint16_t)); 
			calcularChecksum(datagrama, pos, auxchecksum);
			memcpy(datagrama + pos_checksum, auxchecksum, sizeof(uint16_t));

			/*Agregamos segmento*/
			memcpy(datagrama + pos, segmento, longitud_paquete);
			segmento += longitud_paquete;
			
			if(protocolos_registrados[protocolo_inferior](datagrama, longitud_paquete + IP_HLEN, pila_protocolos, &ipdatos) == ERROR){
				printf("Error protocolos_registrados moduloIP (%d)\n", __LINE__);
				return ERROR;
			}
		}
		return OK;
	}
	else{ /*Sin fragmentación*/

		/*Longitud Total*/
		aux16 = htons(longitud + IP_HLEN);
		memcpy(datagrama + pos_len, &aux16, sizeof(uint16_t));

		/*Flags y offset*/
		aux16 = 0;
		memcpy(datagrama + pos_offset, &aux16, sizeof(uint16_t));

		/*Checksum*/
		calcularChecksum(datagrama, pos, auxchecksum);
		memcpy(datagrama + pos_checksum, auxchecksum, sizeof(uint16_t));
	
		/*Agregamos segmento*/
		memcpy(datagrama + pos, segmento, longitud);

	}

  return protocolos_registrados[protocolo_inferior](datagrama, longitud + pos, pila_protocolos, &ipdatos);
}


/****************************************************************************************
 * Nombre: moduloETH                                                                    *
 * Descripcion: Esta funcion implementa el modulo de envio Ethernet                     *
 * Argumentos:                                                                          *
 *  -datagrama: datagrama a enviar                                                      *
 *  -longitud: bytes que componen el datagrama                                          *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: Parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t moduloETH(uint8_t* datagrama, uint32_t longitud, uint16_t* pila_protocolos,void *parametros){
	uint16_t aux16, mtu;
	uint32_t pos = 0;
	uint8_t trama[ETH_FRAME_MAX]={0};
	uint8_t eth_origen[ETH_HLEN];
	
	Parametros ethdatos = *((Parametros*)parametros);
	uint8_t* eth_destino = ethdatos.ETH_destino;
	struct pcap_pkthdr cabecera;
	struct timeval time;

	printf("modulo ETH(fisica) %s %d.\n",__FILE__,__LINE__);

	/*Comprobamos que el tamano de longitud no sea mayor que mtu*/
	if(obtenerMTUInterface(interface, &mtu) == ERROR) return ERROR;
	
	if(mtu < longitud){
		printf("Error moduloETH: tamaño del datagrama supera el mtu\n");
		return ERROR;
	}
	
	/*Direccion ethernet destino*/
	memcpy(trama, eth_destino, ETH_ALEN);
	pos += ETH_ALEN;

	/*Direccion ethernet origen*/
	if (obtenerMACdeInterface(interface, eth_origen) == ERROR) return ERROR;
	memcpy(trama + pos, eth_origen, ETH_ALEN);
	pos += ETH_ALEN;

	/*Tipo Ethernet*/
	aux16 = htons(0x0800);
	memcpy(trama + pos, &aux16, sizeof(uint16_t));
	pos += sizeof(uint16_t);

	/*Agregamos datagrama*/
	memcpy(trama + pos, datagrama, longitud);
	
	/*Comprobamos que el flag de mostrar esta activado*/
	if(flag_mostrar == 1){
		mostrarHex(trama, pos + longitud);
	}	

	/*Enviamos a capa física*/
	if (pcap_inject(descr, trama, ETH_HLEN + longitud) == ERROR){
		printf("Error moduloETH: pcap_inject returns PCAP_ERROR\n");
		return ERROR;
	}

	/*Completamos cabecera y hacemos el pcap_dump*/
	gettimeofday(&time,NULL);
	cabecera.ts = time;
	cabecera.len = longitud + ETH_HLEN;
	cabecera.caplen = longitud + ETH_HLEN;

	if(pdumper) pcap_dump((uint8_t*)pdumper, &cabecera, trama);

	return OK;
}



/***************************Funciones auxiliares a implementar***********************************/

/****************************************************************************************
 * Nombre: aplicarMascara                                                               *
 * Descripcion: Esta funcion aplica una mascara a una vector                            *
 * Argumentos:                                                                          *
 *  -IP: IP a la que aplicar la mascara en orden de red                                 *
 *  -mascara: mascara a aplicar en orden de red                                         *
 *  -longitud: bytes que componen la direccion (IPv4 == 4)                              *
 *  -resultado: Resultados de aplicar mascara en IP en orden red                        *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t aplicarMascara(uint8_t* IP, uint8_t* mascara, uint8_t longitud, uint8_t* resultado){
	uint32_t i;

	if(!IP || !mascara || longitud < 0 || !resultado) return ERROR;

	for(i = 0; i < longitud; i++){
		resultado[i] = IP[i] & mascara[i];
	}
	return OK;
	}


/***************************Funciones auxiliares implementadas**************************************/

/****************************************************************************************
 * Nombre: mostrarHex                                                                   *
 * Descripcion: Esta funcion imprime por pantalla en hexadecimal un vector              *
 * Argumentos:                                                                          *
 *  -datos: bytes que conforman un mensaje                                              *
 *  -longitud: Bytes que componen el mensaje                                            *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t mostrarHex(uint8_t * datos, uint32_t longitud){
	uint32_t i;
	printf("Datos:\n");
	for (i = 0; i < longitud; i++){
		printf("%02"PRIx8" ", datos[i]);
	}
	printf("\n");
	return OK;
}


/****************************************************************************************
 * Nombre: calcularChecksum                                                             *
 * Descripcion: Esta funcion devuelve el ckecksum tal como lo calcula IP/ICMP           *
 * Argumentos:                                                                          *
 *   -datos: datos sobre los que calcular el checksum                                   *
 *   -longitud: numero de bytes de los datos sobre los que calcular el checksum         *
 *   -checksum: checksum de los datos (2 bytes) en orden de red!                        *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t calcularChecksum(uint8_t *datos, uint16_t longitud, uint8_t *checksum) {
    uint16_t word16;
    uint32_t sum = 0;
    int i;
    /* make 16 bit words out of every two adjacent 8 bit words in the packet
       and add them up*/
    for (i = 0; i < longitud; i += 2){
        word16 = (datos[i] << 8) + datos[i+1];
        sum += (uint32_t)word16;
    }
    /*take only 16 bits out of the 32 bit sum and add up the carries*/
    while (sum >> 16) {
        sum = (sum & 0xFFFF)+(sum >> 16);
    }
    /* one's complement the result*/
    sum =  ~sum;
    checksum[0] = sum >> 8;
    checksum[1] = sum & 0xFF;
    return OK;
}


/***************************Funciones inicializacion implementadas*********************************/

/****************************************************************************************
 * Nombre: inicializarPilaEnviar                                                        *
 * Descripcion: inicializar la pila de red para enviar registrando los distintos modulos*
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t inicializarPilaEnviar() {
	bzero(protocolos_registrados, MAX_PROTOCOL*sizeof(pf_notificacion));
	if(registrarProtocolo(ETH_PROTO, moduloETH, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(IP_PROTO, moduloIP, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(ICMP_PROTO, moduloICMP, protocolos_registrados)==ERROR)
			return ERROR;
	if(registrarProtocolo(UDP_PROTO, moduloUDP, protocolos_registrados)==ERROR)
			return ERROR;

	return OK;
}


/****************************************************************************************
 * Nombre: registrarProtocolo                                                           *
 * Descripcion: Registra un protocolo en la tabla de protocolos                         *
 * Argumentos:                                                                          *
 *  -protocolo: Referencia del protocolo (ver RFC 1700)                                 *
 *  -handleModule: Funcion a llamar con los datos a enviar                              *
 *  -protocolos_registrados: vector de funciones registradas                            *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/

uint8_t registrarProtocolo(uint16_t protocolo, pf_notificacion handleModule, pf_notificacion* protocolos_registrados){
	if(protocolos_registrados == NULL ||  handleModule == NULL){
		printf("Error: registrarProtocolo(): entradas nulas.\n");
		return ERROR;
	}
	else
		protocolos_registrados[protocolo] = handleModule;
	return OK;
}
