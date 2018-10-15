/**
 * Practica 1 Redes de Comunicación 1
 * Autor Lucia Rivas <lucia.rivasmolina@estudiante.uam.es
 * Autor Daniel Santo-Tomas <daniel.santo-tomas@estudiante.uam.es>
 */
#include "practica1.h"
#define SUCCESS 1
#define FAILURE 0

/*Variables globales*/
pcap_t *descr = NULL, *descr2 = NULL;
pcap_dumper_t *pdumper = NULL;
int contador = 0;
int nargs = 0;

/**
 * Funcion capturadora de la sennal Ctrl-C
 * @param sennal capturada
 */
 void captura(int sennal){
	if(sennal == SIGINT){
      printf("Control C pulsado\n");
		printf("Se han capturado %d paquetes\n", contador);
	if(descr)
		pcap_close(descr);
	if(descr2)
		pcap_close(descr2);
	if(pdumper)
		pcap_dump_close(pdumper);
	exit(SUCCESS);
    }
}

/**
 * Funcion callback del pcap_loop para un argumento
 */
 void callback(uint8_t *nbytes, const struct pcap_pkthdr* cabecera, const uint8_t* paquete){
	 int n, i;
	 if(!nbytes || !cabecera || !paquete) return;
	 /*Aumentamos el contador*/
	 contador++;

	 /*Modificamos la cabecera*/
	 struct pcap_pkthdr *cabecera2 = malloc(sizeof(struct pcap_pkthdr));
	 if(!cabecera2) return;

	 cabecera2->ts.tv_sec = cabecera->ts.tv_sec + 1800;
	 cabecera2->ts.tv_usec = cabecera->ts.tv_usec;
	 cabecera2->len = cabecera->len;
	 cabecera2->caplen = cabecera->caplen;

    /*Si solo hay un argumento imprimimos la cabecera modificada*/
    if(nargs == 2){
      printf("Nuevo paquete capturado a las %s",ctime((const time_t*)&(cabecera2->ts.tv_sec)));
   }
   else{
      printf("Paquete capturado a las %s",ctime((const time_t*)&(cabecera->ts.tv_sec)));
   }

	 n = (int)nbytes;
	 
	 /*Si caplen es mas pequenno que nbytes solo imprime caplen*/
	 for(i = 0; i < n && i < cabecera->caplen; i++) printf("%02X ", *(paquete+i));
	 printf("\n\n");

	 /*Guardamos el dumper*/
	 if(pdumper){
		 pcap_dump((uint8_t*)pdumper, cabecera2, paquete);
     }
     free(cabecera2);
}


/**
 * Main de la practica 1
 */
int main(int argc, char** argv){
   char file_name[TAM_CADENA];
   char errbuf[PCAP_ERRBUF_SIZE];
   int nbytes = 0, loop_return;
   struct timeval time;

   /*En caso de no introducir nada muestra ayuda*/
   if(argc < 2){
      printf("No ha introducido ningún parámetro de entrada\n");
      printf("Para capturar una interfaz de n bytes: ./practica1 <n>\n");
      printf("\tEjemplo de interfaz de 3 bytes: ./practica1 3\n\n");
      printf("Para analizar una traza: ./practica1 <n> <traza>\n");
      printf("\tEjemplo de traza de 4 bytes: ./pratica1 4 traza.pcap\n");
      exit(FAILURE);
   }

   nbytes = atoi(argv[1]);
   nargs = argc;

   /*Establecemos la captura de la sennal SIGINT*/
   if(signal(SIGINT, captura) == SIG_ERR){
		printf("Error: Fallo al capturar la sennal SIGINT.\n");
		exit(FAILURE);
	}

   /*Si metemos dos argumentos el descriptor sera la traza pasada*/
   if(argc == 3){
      if((descr = pcap_open_offline(argv[2], errbuf)) == NULL){
         printf("Error: pcap_open_iffline(): %s, %s %d.\n", errbuf, __FILE__, __LINE__);
         exit(FAILURE);
      }
      /*Analiza la traza*/
      loop_return = pcap_loop(descr, -1, callback, (uint8_t*)nbytes);
   }

   /*Si metemos un argumento, apertura de interface para captura*/
   else if(argc == 2){
	   if ((descr = pcap_open_live("eth0", nbytes, 0, 100, errbuf)) == NULL){
         printf("Error: pcap_open_live(): %s, %s %d.\n", errbuf, __FILE__, __LINE__);
         exit(FAILURE);
      }

	   /*Volcado de traza (solo para un argumento)*/
	   if ((descr2 = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX)) == NULL){
		  printf("Error al abrir el dump\n");
		  pcap_close(descr);
		  exit(FAILURE);
	   }
	   gettimeofday(&time,NULL);
	   sprintf(file_name,"captura.eth0.%lld.pcap",(long long)time.tv_sec);
	   if((pdumper = pcap_dump_open(descr2, file_name)) == NULL){
		  printf("Error al abrir el dumper: %s, %s %d.\n", pcap_geterr(descr2),__FILE__,__LINE__);
		  pcap_close(descr);
		  pcap_close(descr2);
		  exit(FAILURE);
	   }

	   /*Analiza la traza*/
	   loop_return = pcap_loop(descr, -1, callback, (uint8_t*)nbytes);
   }
   /*Caso de error en los argumentos*/
   else {
      printf("Error, los argumentos deben ser 1 o 2\n");
      exit(FAILURE);
   }

   /*En caso de error*/
   if(loop_return == -1){
	  printf("Error al capturar un paquete %s, %s %d.\n",pcap_geterr(descr), __FILE__, __LINE__);
	  pcap_close(descr);
	  exit(FAILURE);
   }
   /*Si es interrumpido por pcap_breakloop()*/
   else if(loop_return == -2){
	   printf("Programa %s %d interrumpido por pcap_breakloop()\n", __FILE__, __LINE__);
   }
   /*Si se supera el limite de paquetes*/
   else if(loop_return == 0){
	   printf("Leídos los %d paquetes totales.\n", contador);
   }

   /*Liberamos y cerramos*/
   if(pdumper) pcap_close(descr);
   if(descr) pcap_close(descr);
   if(descr2) pcap_close(descr2);

   exit(SUCCESS);
}
