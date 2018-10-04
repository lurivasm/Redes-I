/**
 * Practica 1 Redes de Comunicación 1
 * @author Lucia Rivas <lucia.rivasmolina@estudiante.uam.es
 * @author Daniel Santo-Tomas <daniel.santo-tomas@estudiante.uam.es>
 */
#include <practica1.h>

int main(int argc, char** argv){
   pcap_t *descr = NULL, *descr2 = NULL;
   pcap_dumper_t *pdumper = NULL;
   char file_name[TAM_CADENA];
   char errbuf[PCAP_ERRBUF_SIZE];
   int nbytes = 0;

   /*En caso de no introducir nada muestra ayuda*/
   if(argc <= 2){
      printf("No ha introducido ningún parámetro de entrada\n");
      printf("Para capturar una interfaz de n bytes: ./practica1 <n>\n");
      printf("\tEjemplo de interfaz de 3 bytes: ./practica1 3\n\n");
      printf("Para analizar una traza: ./practica1 <n> <traza>\n");
      printf("\tEjemplo de traza de 4 bytes: ./pratica1 4 traza.pcap\n");
      exit(FAILURE);
   }

   /*Establecemos la captura de la sennal SIGINT*/
   if(signal(SIGINT, captura) == SIG_ERR){
		printf("Error: Fallo al capturar la sennal SIGINT.\n");
		exit(FAILURE);
	}

   /*Si metemos dos argumentos el descriptor sera la traza pasada*/
   if(argc == 4){
      if((descr = pcap_open_offline(argv[3], errbuf)) == NULL)){
         printf("Error: pcap_open_iffline(): %s, %s %d.\n", errbuf, __FILE__, __LINE__);
         exit(FAILURE);
      }
   }

   /*Apertura de interface para captura*/
   if(argc == 3){
      if ((descr = pcap_open_live("eth0", 5, 0, 100, errbuf)) == NULL){
         printf("Error: pcap_open_live(): %s, %s %d.\n", errbuf, __FILE__, __LINE__);
         exit(FAILURE);
      }
   }

   /*Volcado de traza*/
   if ((descr2 = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX)) == NULL){
      printf("Error al abrir el dump\n");
      pcap_close(descr);
      exit(ERROR);
   }
   gettimeofday(&time,NULL);
   sprintf(file_name,"captura.eth0.%lld.pcap",(long long)time.tv_sec);
   if((pdumper = pcap_dump_open(descr2, file_name)) == NULL){
      printf("Error al abrir el dumper: %s, %s %d.\n",pcap_geterr(descr2),__FILE__,__LINE__);
      pcap_close(descr);
      pcap_close(descr2);
      exit(ERROR);
   }


   pcap_dump_close(pdumper);
	pcap_close(descr);
	pcap_close(descr2);
   exit(SUCCESS);
}
