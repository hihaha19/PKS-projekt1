#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#define GENERAL_ERROR	3
#define SUCCESS	0
#define PROTOCOL_BUFFER_SIZE 20
#define GENERAL_BUFFER_SIZE 100

typedef struct Ramec {
	struct pcap_pkthdr pcap_hlavicka;
	u_char* smernik_na_data;
}RAMEC;

typedef struct IP_adresy {
	u_char ip_adresa[15];
	int pocet_paketov;
	int pocet_ip_adries;
}IP_ADRESY;

typedef struct Tftp_komunikacia {
	int poradove_cislo;
	int cislo_ramca;
	char zdrojova_ip[GENERAL_BUFFER_SIZE];
	char cielova_ip[GENERAL_BUFFER_SIZE];
}TFTP_KOMUNIKACIA;

typedef struct Arp_komunikacia {
	int cislo_ramca;
	char typ[GENERAL_BUFFER_SIZE];
	char opcode[2];
	int pocet_ramcov;
	char zdrojova_ip[GENERAL_BUFFER_SIZE];
	char cielova_ip[GENERAL_BUFFER_SIZE];
	char zdrojova_mac[GENERAL_BUFFER_SIZE];
	int sparovany_request;
	int sparovany_reply;
	int pocet_requestov_bez_reply;
	int pocet_reply_bez_request;
}ARP_KOMUNIKACIA;

typedef struct Icmp_komunikacia {
	int cislo_ramca;
	int pocet_ramcov_v_strukture;
	char typ[GENERAL_BUFFER_SIZE];
}ICMP_KOMUNIKACIA;

typedef struct Tcp_komunikacia {
	int poradove_cislo_v_strukture;
	int poradove_cislo_v_ramci;
	int pocet_ramcov_v_strukture;
	char typ_protokolu[PROTOCOL_BUFFER_SIZE];
	int pocet_http;
	int pocet_https;
	int pocet_telnet;
	int pocet_ssh;
	int pocet_ftp_riadiace;
	int pocet_ftp_datove;
	char cielova_ip[GENERAL_BUFFER_SIZE];
	char zdrojova_ip[GENERAL_BUFFER_SIZE];
}TCP_KOMUNIKACIA;

typedef struct Nekompletna_komunikacia {
	int cislo_v_ramci;
	int zaplnena;
}NEKOMPLETNA_KOMUNIKACIA;

typedef struct Kompletna_komunikacia {
	int cislo_v_ramci;
	int zaplnena;
}KOMPLETNA_KOMUNIKACIA;

int vypis_bajty(u_char* data, bpf_u_int32 caplen, FILE* vystupny_subor) {

	int rv = GENERAL_ERROR;

	if (0 >= caplen || NULL == data) {
		fprintf(vystupny_subor, "Zle parametre vo funkcii vypis bajty\n");
		goto err;
	}

	for (u_int i = 0; (i < caplen); i++) {
		if (i % 8 == 0 && i % 16 != 0)
			fputc(' ', vystupny_subor);
		else if (i % 16 == 0 && i != 0)
			fputc('\n', vystupny_subor);
		fprintf(vystupny_subor, "%.2x ", data[i]);
	}

	rv = SUCCESS;

err:

	return rv;
}


int vypis_MAC_adresy(u_char* data, FILE* vystupny_subor) {
	int rv = GENERAL_ERROR;
	int o;

	fprintf(vystupny_subor, "Zdrojova MAC adresa: ");
	for (o = 6; o < 11; o++)
		fprintf(vystupny_subor, "%.2x ", data[o]);
	fprintf(vystupny_subor, "%.2x\n", data[11]);

	fprintf(vystupny_subor, "Cielova MAC adresa: ");
	for (o = 0; o < 5; o++)
		fprintf(vystupny_subor, "%.2x ", data[o]);
	fprintf(vystupny_subor, "%.2x\n", data[5]);

	rv = SUCCESS;
	return rv;
}



int zisti_ethernet2_protokol(u_char* data, FILE* subor_s_protokolmi_a_portmi, char protokol[], int velkost, char typ_ramca[]) {
	char cislo[8];
	char prve_2_znaky[3], druhe_2_znaky[3], tretie_2_znaky[3];
	char ether[] = "#EtherTypes";
	char nazov[26];
	char medzera[2];
	char nazov_pola[12];
	int nacitane_data = -1, hladane_data = -2;
	char jeden_byte[3] = { 0 }, druhy_byte[3] = { 0 };

	if (strcmp(typ_ramca, "EthernetII") == 0) {
		sprintf(jeden_byte, "%.2x", data[12]);
		sprintf(druhy_byte, "%.2x", data[13]);
	}

	else if (strcmp(typ_ramca, "Snap") == 0) {
		sprintf(jeden_byte, "%.2x", data[20]);
		sprintf(druhy_byte, "%.2x", data[21]);
	}

	fseek(subor_s_protokolmi_a_portmi, 0, 0);

	fgets(nazov_pola, 12, subor_s_protokolmi_a_portmi);
	fgets(medzera, 2, subor_s_protokolmi_a_portmi);


	if (strcmp(nazov_pola, ether) == 0) {
		while (nacitane_data != hladane_data)
		{
			if (NULL == fgets(prve_2_znaky, 3, subor_s_protokolmi_a_portmi)) return 0;
			if (strcmp(prve_2_znaky, "#L") == 0) 	return 0;
			fgets(druhe_2_znaky, 3, subor_s_protokolmi_a_portmi);
			fgets(tretie_2_znaky, 3, subor_s_protokolmi_a_portmi);
			fgets(medzera, 2, subor_s_protokolmi_a_portmi);
			fgets(nazov, 26, subor_s_protokolmi_a_portmi);
			fgets(medzera, 1, subor_s_protokolmi_a_portmi);
			if ((strcmp(druhe_2_znaky, jeden_byte) == 0) && (strcmp(tretie_2_znaky, druhy_byte) == 0))
			{
				nacitane_data = 1;
				hladane_data = 1;
			}
		}
	}

	if (nacitane_data == hladane_data)
	{
		strncpy(protokol, nazov, velkost);
		return 0;
	}
}

int zisti_LLC_protokol(u_char* data, FILE* subor_s_protokolmi_a_portmi, char protokol[], int velkost, int uloha) {
	char lsap[] = "#LSAPs";
	char nazov_pola[7];
	char prve_2_znaky[3];
	char druhe_2_znaky[3];
	int nacitane_data = -1, hladane_data = -2;
	char nazov[34];
	char medzera[2];
	char patnasty_byte[3];
	fseek(subor_s_protokolmi_a_portmi, 0, 0);

	sprintf(patnasty_byte, "%.2x", data[14]);

	fgets(nazov_pola, 7, subor_s_protokolmi_a_portmi);
	while (strcmp(nazov_pola, lsap) != 0) {
		fgets(nazov_pola, 7, subor_s_protokolmi_a_portmi);
	}

	while (nacitane_data != hladane_data) {
		if (NULL == fgets(prve_2_znaky, 3, subor_s_protokolmi_a_portmi)) return 0;
		if (strcmp(prve_2_znaky, "#I") == 0) 	return 0;
		fgets(druhe_2_znaky, 3, subor_s_protokolmi_a_portmi);
		fgets(medzera, 2, subor_s_protokolmi_a_portmi);
		fgets(nazov, 34, subor_s_protokolmi_a_portmi);
		fgets(medzera, 1, subor_s_protokolmi_a_portmi);

		if (strcmp(druhe_2_znaky, patnasty_byte) == 0)
		{
			nacitane_data = 1;
			hladane_data = 1;
		}
	}

	if (nacitane_data == hladane_data)
	{
		strncpy(protokol, nazov, velkost);
		return 0;
	}
	return 0;
}

int vypis_tcp_portov(u_char* data, FILE* subor_s_protokolmi_a_portmi, FILE *vystupny_subor, char protokol[], char cielovy_port[], char cislo_cieloveho_portu[], char zdrojovy_port[], char cislo_zdrojoveho_portu[], int uloha) {
	char tcp[] = "#TCP porty\n";
	// cielovy_port, cislo_cieloveho_portu, zdrojovy_port, cislo_zdrojoveho_portu
	char nazov_pola[12];
	char prve_2_znaky[3];
	char druhe_2_znaky[3];
	char tretie_2_znaky[3];
	int nacitane_data = -1, hladane_data = -2;
	char nazov[14];
	char medzera[2]; 
	char port_v_desiatkovej[5] = { 0 };
	char prvy_byte_zdrojovy[3], druhy_byte_zdrojovy[3], prvy_byte_cielovy[3], druhy_byte_cielovy[3];
	int cislo = 0;
	int port_v_subore = 1;

	fseek(subor_s_protokolmi_a_portmi, 0, 0);
	sprintf(prvy_byte_zdrojovy, "%.2x", data[34]);
	sprintf(druhy_byte_zdrojovy, "%.2x", data[35]);
	fgets(nazov_pola, 12, subor_s_protokolmi_a_portmi);

	while (strcmp(nazov_pola, tcp) != 0) 
		fgets(nazov_pola, 12, subor_s_protokolmi_a_portmi);
	
	while (nacitane_data != hladane_data) {
		if (NULL == fgets(prve_2_znaky, 3, subor_s_protokolmi_a_portmi)) break;
		if (strcmp(prve_2_znaky, "#U") == 0) 	break;
			
		fgets(druhe_2_znaky, 3, subor_s_protokolmi_a_portmi);
		fgets(tretie_2_znaky, 3, subor_s_protokolmi_a_portmi);
		fgets(medzera, 2, subor_s_protokolmi_a_portmi);
		fscanf(subor_s_protokolmi_a_portmi, "%s", port_v_desiatkovej);


		fgets(medzera, 2, subor_s_protokolmi_a_portmi);
		fgets(nazov, 14, subor_s_protokolmi_a_portmi);
		fgets(medzera, 1, subor_s_protokolmi_a_portmi);
		if ((strcmp(druhe_2_znaky, prvy_byte_zdrojovy) == 0) && (strcmp(tretie_2_znaky, druhy_byte_zdrojovy) == 0)) {
			nacitane_data = 1;
			hladane_data = 1;
		}
	}

		if (nacitane_data == hladane_data) {
			if(nazov != NULL || port_v_desiatkovej != NULL) 
				//fprintf(vystupny_subor, "%sZdrojovy port: %s\n", nazov, port_v_desiatkovej);
			strcpy(zdrojovy_port, nazov);
			strcpy(cislo_zdrojoveho_portu, port_v_desiatkovej);
		}

	nacitane_data = -1; hladane_data = -2;
	char hladam_tcp[12];

	fseek(subor_s_protokolmi_a_portmi, 0, 0);
	sprintf(prvy_byte_cielovy, "%.2x", data[36]);
	sprintf(druhy_byte_cielovy, "%.2x", data[37]);

	while (strcmp(hladam_tcp, tcp) != 0)
		fgets(hladam_tcp, 12, subor_s_protokolmi_a_portmi);

	while (nacitane_data != hladane_data) {
		if (NULL == fgets(prve_2_znaky, 3, subor_s_protokolmi_a_portmi)) return 0;
		if (strcmp(prve_2_znaky, "#U") == 0) {
			return 0;
		}

		fgets(druhe_2_znaky, 3, subor_s_protokolmi_a_portmi);
		fgets(tretie_2_znaky, 3, subor_s_protokolmi_a_portmi);
		fgets(medzera, 2, subor_s_protokolmi_a_portmi);
		fscanf(subor_s_protokolmi_a_portmi, "%s", port_v_desiatkovej);


		fgets(medzera, 2, subor_s_protokolmi_a_portmi);
		fgets(nazov, 14, subor_s_protokolmi_a_portmi);
		fgets(medzera, 1, subor_s_protokolmi_a_portmi);
		if ((strcmp(druhe_2_znaky, prvy_byte_cielovy) == 0) && (strcmp(tretie_2_znaky, druhy_byte_cielovy) == 0)) {
			nacitane_data = 1;
			hladane_data = 1;
		}
	}

	if (nacitane_data == hladane_data && uloha != 0 && uloha != 1)	{
		if(port_v_desiatkovej != "") fprintf(vystupny_subor, "%sCielovy port: %s\n", nazov, port_v_desiatkovej);
		 strcpy(cielovy_port, nazov);
		 strcpy(cislo_cieloveho_portu, port_v_desiatkovej);
	}

	return 0;
}

int vypis_udp_portov(u_char* data, FILE* subor_s_protokolmi_a_portmi, FILE * vystupny_subor, char protokol[], char cielovy_port[], char zdrojovy_port[], int uloha) {
	char udp[] = "#UDP porty\n";
	char nazov_pola[12];
	char prve_2_znaky[3];
	char druhe_2_znaky[3];
	char tretie_2_znaky[3];
	int nacitane_data = -1, hladane_data = -2;
	char nazov[12];
	char medzera[2];
	char prvy_byte_zdrojovy[3], druhy_byte_zdrojovy[3], prvy_byte_cielovy[3], druhy_byte_cielovy[3];
	char port_v_desiatkovej[6];

	fseek(subor_s_protokolmi_a_portmi, 0, 0);
	sprintf(prvy_byte_zdrojovy, "%.2x", data[34]);
	sprintf(druhy_byte_zdrojovy, "%.2x", data[35]);

	fgets(nazov_pola, 12, subor_s_protokolmi_a_portmi);
	while (strcmp(nazov_pola, udp) != 0) {
		fgets(nazov_pola, 12, subor_s_protokolmi_a_portmi);
	}

		while (nacitane_data != hladane_data) {
			if (NULL == fgets(prve_2_znaky, 3, subor_s_protokolmi_a_portmi)) break;
			
			fgets(druhe_2_znaky, 3, subor_s_protokolmi_a_portmi);
			fgets(tretie_2_znaky, 3, subor_s_protokolmi_a_portmi);
			fgets(medzera, 2, subor_s_protokolmi_a_portmi);
			fscanf(subor_s_protokolmi_a_portmi, "%s", port_v_desiatkovej);

			fgets(medzera, 2, subor_s_protokolmi_a_portmi);
			fgets(nazov, 12, subor_s_protokolmi_a_portmi);
			fgets(medzera, 1, subor_s_protokolmi_a_portmi);
			if ((strcmp(druhe_2_znaky, prvy_byte_zdrojovy) == 0) && (strcmp(tretie_2_znaky, druhy_byte_zdrojovy) == 0)) {
				nacitane_data = 1;
				hladane_data = 1;
			}
		}

		if (hladane_data == nacitane_data) {
			if(port_v_desiatkovej != "" && uloha != 0 && uloha !=  1) fprintf(vystupny_subor, "%sZdrojovy port: %s\n", nazov, port_v_desiatkovej);
			strcpy(zdrojovy_port, nazov);
		}

	char hladam_udp[12];

	fseek(subor_s_protokolmi_a_portmi, 0, 0);
	sprintf(prvy_byte_cielovy, "%.2x", data[36]);
	sprintf(druhy_byte_cielovy, "%.2x", data[37]);

	fgets(hladam_udp, 12, subor_s_protokolmi_a_portmi);
	while (strcmp(hladam_udp, udp) != 0) 
		fgets(hladam_udp, 12, subor_s_protokolmi_a_portmi);
	
		while (nacitane_data != hladane_data) {
			if (NULL == fgets(prve_2_znaky, 3, subor_s_protokolmi_a_portmi)) return 0;
			fgets(druhe_2_znaky, 3, subor_s_protokolmi_a_portmi);
			fgets(tretie_2_znaky, 3, subor_s_protokolmi_a_portmi);
			fgets(medzera, 2, subor_s_protokolmi_a_portmi);
			fscanf(subor_s_protokolmi_a_portmi, "%s", port_v_desiatkovej);

			fgets(medzera, 2, subor_s_protokolmi_a_portmi);
			fgets(nazov, 12, subor_s_protokolmi_a_portmi);
			fgets(medzera, 1, subor_s_protokolmi_a_portmi);
			if ((strcmp(druhe_2_znaky, prvy_byte_cielovy) == 0) && (strcmp(tretie_2_znaky, druhy_byte_cielovy) == 0)) {
				nacitane_data = 1;
				hladane_data = 1;
			}
		}

		if (nacitane_data == hladane_data) {
			if (port_v_desiatkovej != "" && uloha != 0 && uloha != 1) fprintf(vystupny_subor, "%sCielovy port: %s\n", nazov, port_v_desiatkovej);
			strcpy(cielovy_port, nazov);
		}
	
	return 0;
}

int zisti_transportny_protokol(u_char* data, FILE* subor_s_protokolmi_a_portmi, char protokol[]) {
	char ip_protokoly[] = "#IP protokoly";
	char nazov_pola[14];
	char prve_2_znaky[3];
	char druhe_2_znaky[3];
	int nacitane_data = -1, hladane_data = -2;
	char nazov[5];
	char medzera[2];
	char prvy_byte[3];
	char protokol_v_desiatkovej[2];

	fseek(subor_s_protokolmi_a_portmi, 0, 0);

	sprintf(prvy_byte, "%.2x", data[23]);

	fgets(nazov_pola, 14, subor_s_protokolmi_a_portmi);
	while (strcmp(nazov_pola, ip_protokoly) != 0) 
		fgets(nazov_pola, 14, subor_s_protokolmi_a_portmi);
	fgets(medzera, 2, subor_s_protokolmi_a_portmi);
	

	while (nacitane_data != hladane_data) {
		if (NULL == fgets(prve_2_znaky, 3, subor_s_protokolmi_a_portmi)) break;
		if (strcmp(prve_2_znaky, "#T") == 0) {
			return 0;
		}
		fgets(druhe_2_znaky, 3, subor_s_protokolmi_a_portmi);
		fgets(medzera, 2, subor_s_protokolmi_a_portmi);
		fgets(protokol_v_desiatkovej, 2, subor_s_protokolmi_a_portmi);
		if(protokol_v_desiatkovej[1] == '\0') fgets(medzera, 2, subor_s_protokolmi_a_portmi);
		else fgets(medzera, 1, subor_s_protokolmi_a_portmi);
		fscanf(subor_s_protokolmi_a_portmi, "%s", nazov);
		fgets(medzera, 2, subor_s_protokolmi_a_portmi);

		if (strcmp(druhe_2_znaky, prvy_byte) == 0) {
			nacitane_data = 1;
			hladane_data = 1;
		}
	}
	if (hladane_data == nacitane_data) 	strcpy(protokol, nazov);
}

int vypis_tftp_komunikaciu(int poradove_cislo, RAMEC* ramce, u_char *data) {
	int i = poradove_cislo; //poradove cislo ramca
	int pocet_ramcov_komunikacii = 0;
	int alokuj = 1;
	TFTP_KOMUNIKACIA* komunikacia = NULL;
	char zdrojovy_port_aktualneho[5], zdrojovy_port_dalsieho_ramca[5], cielovy_port_aktualneho[5], cielovy_port_dalsieho_ramca[5];
	char ip_zdrojova_aktualneho[GENERAL_BUFFER_SIZE], ip_cielova_aktualneho[GENERAL_BUFFER_SIZE];
	char ip_zdrojova_dalsieho_ramca[GENERAL_BUFFER_SIZE], ip_cielova_dalsieho_ramca[GENERAL_BUFFER_SIZE];

	sprintf(zdrojovy_port_aktualneho, "%.2x%.2x", ramce[i - 1].smernik_na_data[34], ramce[i - 1].smernik_na_data[35]);
	sprintf(cielovy_port_aktualneho, "%.2x%.2x", ramce[i-1].smernik_na_data[36], ramce[i-1].smernik_na_data[37]);
	sprintf(ip_zdrojova_aktualneho, "%d.%d.%d.%d", ramce[i-1].smernik_na_data[26], ramce[i-1].smernik_na_data[27],
		ramce[i-1].smernik_na_data[28], ramce[i-1].smernik_na_data[29]);
	sprintf(ip_cielova_aktualneho, "%d.%d.%d.%d", ramce[i - 1].smernik_na_data[30], ramce[i - 1].smernik_na_data[31],
		ramce[i - 1].smernik_na_data[32], ramce[i - 1].smernik_na_data[32]);

	sprintf(zdrojovy_port_dalsieho_ramca, "%.2x%.2x", ramce[i].smernik_na_data[34], ramce[i].smernik_na_data[35]);
	sprintf(cielovy_port_dalsieho_ramca, "%.2x%.2x", ramce[i].smernik_na_data[36], ramce[i].smernik_na_data[37]);
	sprintf(ip_zdrojova_dalsieho_ramca, "%d.%d.%d.%d", ramce[i].smernik_na_data[26], ramce[i].smernik_na_data[27],
		ramce[i].smernik_na_data[28], ramce[i].smernik_na_data[29]);
	sprintf(ip_cielova_dalsieho_ramca, "%d.%d.%d.%d", ramce[i].smernik_na_data[30], ramce[i].smernik_na_data[31],
		ramce[i].smernik_na_data[32], ramce[i].smernik_na_data[32]);
	//ip 1 port 1 je source, ip2 port 2 je destination, skusam ci ma dalsi ramec 1 ako source a 2 ako dest
	//alebo opacne
	//kym sucasny zdrojovy a buduci cielovy sa rovnaju, dalsi ramec ma zdrojovu_ip ako zdrojovu alebo cielovu
	while (((strcmp(zdrojovy_port_aktualneho, cielovy_port_dalsieho_ramca)==0) && (strcmp(ip_zdrojova_aktualneho, ip_cielova_dalsieho_ramca) == 0) &&
	(strcmp(ip_cielova_aktualneho, ip_zdrojova_dalsieho_ramca) == 0)) || ((strcmp(ip_zdrojova_aktualneho, ip_zdrojova_dalsieho_ramca) == 0) &&
	(strcmp(ip_cielova_aktualneho, ip_cielova_dalsieho_ramca) == 0) && (strcmp(zdrojovy_port_aktualneho, zdrojovy_port_dalsieho_ramca) == 0) &&
	(strcmp(cielovy_port_aktualneho, cielovy_port_dalsieho_ramca) == 0))){
		komunikacia = (TFTP_KOMUNIKACIA*)realloc(komunikacia, alokuj * sizeof(TFTP_KOMUNIKACIA));
		komunikacia[pocet_ramcov_komunikacii].poradove_cislo = pocet_ramcov_komunikacii + 1;
		komunikacia[pocet_ramcov_komunikacii].cislo_ramca = i;
		pocet_ramcov_komunikacii++;
		alokuj++;
		i++;
		sprintf(zdrojovy_port_aktualneho, "%.2x%.2x", ramce[i - 1].smernik_na_data[34], ramce[i - 1].smernik_na_data[35]);
		sprintf(cielovy_port_aktualneho, "%.2x%.2x", ramce[i - 1].smernik_na_data[36], ramce[i - 1].smernik_na_data[37]);
		sprintf(ip_zdrojova_aktualneho, "%d.%d.%d.%d", ramce[i - 1].smernik_na_data[26], ramce[i - 1].smernik_na_data[27],
			ramce[i - 1].smernik_na_data[28], ramce[i - 1].smernik_na_data[29]);
		sprintf(ip_cielova_aktualneho, "%d.%d.%d.%d", ramce[i - 1].smernik_na_data[30], ramce[i - 1].smernik_na_data[31],
			ramce[i - 1].smernik_na_data[32], ramce[i - 1].smernik_na_data[32]);

		sprintf(cielovy_port_dalsieho_ramca, "%.2x%.2x", ramce[i].smernik_na_data[36], ramce[i].smernik_na_data[37]);
		sprintf(zdrojovy_port_dalsieho_ramca, "%.2x%.2x", ramce[i].smernik_na_data[34], ramce[i].smernik_na_data[35]);
		sprintf(ip_zdrojova_dalsieho_ramca, "%d.%d.%d.%d", ramce[i].smernik_na_data[26], ramce[i].smernik_na_data[27],
			ramce[i].smernik_na_data[28], ramce[i].smernik_na_data[29]);
		sprintf(ip_cielova_dalsieho_ramca, "%d.%d.%d.%d", ramce[i].smernik_na_data[30], ramce[i].smernik_na_data[31],
			ramce[i].smernik_na_data[32], ramce[i].smernik_na_data[32]);
	}//v eth-9, trace-15
	//1 komunikacia je pokym spolu porty komunikuju, spolieham sa na porty a ip adresy??
	printf("Pocet komunikacii %d\n", pocet_ramcov_komunikacii);
	for(i = 0; i < pocet_ramcov_komunikacii; i++)
		printf("Ramce v subore: %d cislo komunikacie %d\n", komunikacia[i].cislo_ramca, komunikacia[i].poradove_cislo);
	//dokoncit
}



int arp_dvojice(ARP_KOMUNIKACIA *arp_struktura, RAMEC *ramce, u_char *data, FILE *vystupny_subor, FILE *subor_s_portmi_a_protokolmi) {
	char zdrojova_ip[GENERAL_BUFFER_SIZE], cielova_ip[GENERAL_BUFFER_SIZE];
	char protokol[PROTOCOL_BUFFER_SIZE];
	char ip_adresa_hladanej_mac[GENERAL_BUFFER_SIZE];
	int nasiel_sa_reply = 0;
	int j = 0, k = 0, cislo_komunikacie = 1;
	int requesty_bez_reply = arp_struktura[0].pocet_ramcov;

	j = 0;
	while (strcmp(arp_struktura[j].typ, "request") != 0 && j <arp_struktura[0].pocet_ramcov) j++;

	while (j < arp_struktura[0].pocet_ramcov) {
		if (strcmp(arp_struktura[j].typ, "request") == 0)
		{
			strcpy(ip_adresa_hladanej_mac, arp_struktura[j].cielova_ip);
			while (k < arp_struktura[0].pocet_ramcov && 0 == nasiel_sa_reply) {
				if ((strcmp(ip_adresa_hladanej_mac, arp_struktura[k].zdrojova_ip) == 0) && (strcmp(arp_struktura[k].opcode, "02") == 0)) {
					nasiel_sa_reply = 1;
					arp_struktura[0].pocet_requestov_bez_reply--;
					arp_struktura[0].pocet_reply_bez_request--;
					arp_struktura[j].sparovany_request = 1;
					arp_struktura[k].sparovany_reply = 1;
					break;
				} k++;
			} 
			if (nasiel_sa_reply == 1) {
				fprintf(vystupny_subor, "Komunikacia c. %d\n", cislo_komunikacie);
				fprintf(vystupny_subor, "ARP-Request, IP adresa: %s\t MAC adresa: ???\n", ip_adresa_hladanej_mac);
				fprintf(vystupny_subor, "Zdrojova IP: %s\t Cielova IP: %s\n", arp_struktura[j].zdrojova_ip, arp_struktura[j].cielova_ip);
				
				vypis_dlzky_ramca(ramce[j].pcap_hlavicka.caplen, vystupny_subor);
				vypis_linkovej_vrstvy(j+1, ramce, ramce[j].smernik_na_data, subor_s_portmi_a_protokolmi, vystupny_subor, 0, 0, 0, 0, 0, 0, 1);
				vypis_MAC_adresy(ramce[j].smernik_na_data, vystupny_subor);
				fprintf(vystupny_subor, "\n");
				vypis_bajty(ramce[j].smernik_na_data, ramce[j - 1].pcap_hlavicka.caplen, vystupny_subor);
				fprintf(vystupny_subor, "\n\n");
				fprintf(vystupny_subor, "ARP-Reply, IP adresa: %s\t najdena MAC adresa: %s\n", ip_adresa_hladanej_mac, arp_struktura[k].zdrojova_mac);
				vypis_dlzky_ramca(ramce[k].pcap_hlavicka.caplen, vystupny_subor);
				vypis_linkovej_vrstvy(k+1, ramce, ramce[k].smernik_na_data, subor_s_portmi_a_protokolmi, vystupny_subor, 0, 0, 0, 0, 0, 0, 1);
				vypis_MAC_adresy(ramce[k].smernik_na_data, vystupny_subor);
				fprintf(vystupny_subor, "\n");
				vypis_bajty(ramce[k].smernik_na_data, ramce[k].pcap_hlavicka.caplen, vystupny_subor);
				cislo_komunikacie++;
			} nasiel_sa_reply = 0; j++; k = j;
		} 
		else j++;
	}
	j = 1;

	if (arp_struktura[0].pocet_requestov_bez_reply > 0) {
		fprintf(vystupny_subor, "Nesparovane requesty:\n");
		while (j <= arp_struktura[0].pocet_ramcov) {
			if (arp_struktura[j-1].sparovany_request == 0) fprintf(vystupny_subor, "Ramec c. %d\n", arp_struktura[j-1].cislo_ramca);
			vypis_dlzky_ramca(ramce[j - 1].pcap_hlavicka.caplen, vystupny_subor);
			vypis_linkovej_vrstvy(j, ramce, ramce[j - 1].smernik_na_data, subor_s_portmi_a_protokolmi, vystupny_subor, 0, 0, 0, 0, 0, 0, 1);
			vypis_MAC_adresy(ramce[j - 1].smernik_na_data, vystupny_subor);
			fprintf(vystupny_subor, "\n");
			vypis_bajty(ramce[j - 1].smernik_na_data, ramce[j - 1].pcap_hlavicka.caplen, vystupny_subor);
			j++;
			fprintf(vystupny_subor, "\n\n");
		}
	} 

	if (arp_struktura[0].pocet_reply_bez_request > 0) {
		fprintf(vystupny_subor, "Nesparovane reply:\n");
		j = 1;
		while (j <= arp_struktura[0].pocet_ramcov) {
			if (arp_struktura[j-1].sparovany_reply == 0) fprintf(vystupny_subor, "Ramec c. %d\n", arp_struktura[j-1].cislo_ramca);
			vypis_dlzky_ramca(ramce[j - 1].pcap_hlavicka.caplen, vystupny_subor);
			vypis_linkovej_vrstvy(j, ramce, ramce[j - 1].smernik_na_data, subor_s_portmi_a_protokolmi, vystupny_subor, 0, 0, 0, 0, 0, 0, 1);
			vypis_MAC_adresy(ramce[j - 1].smernik_na_data, vystupny_subor);
			fprintf(vystupny_subor, "\n");
			vypis_bajty(ramce[j - 1].smernik_na_data, ramce[j - 1].pcap_hlavicka.caplen, vystupny_subor);
			j++;
			fprintf(vystupny_subor, "\n\n");
		}
	}
}

int alokuj_strukturu_tcp_komunikacii(RAMEC* ramce, int poradove_cislo, TCP_KOMUNIKACIA** struktura, char cielovy_port[], char zdrojovy_port[]) {
	TCP_KOMUNIKACIA* lokal = *struktura;
	int pocet_ramcov = 0;
	int i = poradove_cislo - 1;
	char cielova_ip[GENERAL_BUFFER_SIZE];
	char zdrojova_ip[GENERAL_BUFFER_SIZE];
	sprintf(cielova_ip, "%d.%d.%d.%d", ramce[i].smernik_na_data[30], ramce[i].smernik_na_data[31], ramce[i].smernik_na_data[32], ramce[i].smernik_na_data[33]);
	sprintf(zdrojova_ip, "%d.%d.%d.%d", ramce[i].smernik_na_data[26], ramce[i].smernik_na_data[27], ramce[i].smernik_na_data[28], ramce[i].smernik_na_data[29]);

	if (*struktura == NULL) {
		lokal = (TCP_KOMUNIKACIA*)realloc(lokal, 1*sizeof(TCP_KOMUNIKACIA));
		lokal[0].poradove_cislo_v_ramci = poradove_cislo;
		strcpy(lokal[0].zdrojova_ip, zdrojova_ip); strcpy(lokal[0].cielova_ip, cielova_ip);

		if (strcmp(cielovy_port, "20") == 0 || strcmp(zdrojovy_port, "20") == 0 || strcmp(cielovy_port, "FTP-DATA\n") == 0 || strcmp(zdrojovy_port, "FTP-DATA\n") == 0) {
			strcpy(lokal[0].typ_protokolu, "FTP-DATA");
			lokal[0].pocet_ftp_datove = 1;
			lokal[0].pocet_ftp_riadiace = 0;
			lokal[0].pocet_http = 0;
			lokal[0].pocet_https = 0;
			lokal[0].pocet_ssh = 0;
			lokal[0].pocet_telnet = 0;
		}
		else if (strcmp(cielovy_port, "21") == 0 || strcmp(zdrojovy_port, "21") == 0 || strcmp(cielovy_port, "FTP-CONTROL\n") == 0 || strcmp(zdrojovy_port, "FTP-CONTROL\n") == 0) {
			strcpy(lokal[0].typ_protokolu, "FTP-CONTROL");
			lokal[0].pocet_ftp_riadiace = 1;
			lokal[0].pocet_ftp_datove = 0;
			lokal[0].pocet_http = 0;
			lokal[0].pocet_https = 0;
			lokal[0].pocet_ssh = 0;
			lokal[0].pocet_telnet = 0;
		}
		else if (strcmp(cielovy_port, "22") == 0 || strcmp(zdrojovy_port, "22") == 0 || strcmp(zdrojovy_port, "SSH\n") == 0 || strcmp(cielovy_port, "SSH\n") == 0) {
			strcpy(lokal[0].typ_protokolu, "SSH");
			lokal[0].pocet_ftp_datove = 0;
			lokal[0].pocet_ftp_riadiace = 0;
			lokal[0].pocet_http = 0;
			lokal[0].pocet_https = 0;
			lokal[0].pocet_telnet = 0;
			lokal[0].pocet_ssh = 1;
		}
		else if (strcmp(cielovy_port, "23") == 0 || strcmp(zdrojovy_port, "23") == 0 || strcmp(cielovy_port, "TELNET\n") == 0 || strcmp(zdrojovy_port, "TELNET\n") == 0) {
			strcpy(lokal[0].typ_protokolu, "TELNET");
			lokal[0].pocet_ftp_datove = 0;
			lokal[0].pocet_ftp_riadiace = 0;
			lokal[0].pocet_http = 0;
			lokal[0].pocet_https = 0;
			lokal[0].pocet_ssh = 0;
			lokal[0].pocet_telnet = 1;
		}

		else if (strcmp(cielovy_port, "80") == 0 || strcmp(zdrojovy_port, "80") == 0 || strcmp(zdrojovy_port, "HTTP\n") == 0 || strcmp(cielovy_port, "HTTP\n") == 0) {
			strcpy(lokal[0].typ_protokolu, "HTTP");
			lokal[0].pocet_ftp_datove = 0;
			lokal[0].pocet_ftp_riadiace = 0;
			lokal[0].pocet_https = 0;
			lokal[0].pocet_ssh = 0;
			lokal[0].pocet_telnet = 0;
			lokal[0].pocet_http = 1;
		}

		else if (strcmp(cielovy_port, "443") == 0 || strcmp(zdrojovy_port, "443") == 0 || strcmp(zdrojovy_port, "HTTPS\n") == 0 || strcmp(cielovy_port, "HTTPS\n") == 0) {
			strcpy(lokal[0].typ_protokolu, "HTTPS");
			lokal[0].poradove_cislo_v_ramci = poradove_cislo;
			lokal[0].pocet_ftp_datove = 0;
			lokal[0].pocet_ftp_riadiace = 0;
			lokal[0].pocet_ssh = 0;
			lokal[0].pocet_telnet = 0;
			lokal[0].pocet_http = 0;
			lokal[0].pocet_https = 1;
		}
	
		lokal[0].pocet_ramcov_v_strukture = 1;
		*struktura = lokal;
		return 0;
	}

	else {
		lokal[0].pocet_ramcov_v_strukture++;
		pocet_ramcov = lokal[0].pocet_ramcov_v_strukture;
		lokal = (TCP_KOMUNIKACIA*)realloc(lokal, pocet_ramcov * sizeof(TCP_KOMUNIKACIA));
		lokal[pocet_ramcov - 1].poradove_cislo_v_ramci = poradove_cislo;

		strcpy(lokal[pocet_ramcov-1].zdrojova_ip, zdrojova_ip); strcpy(lokal[pocet_ramcov - 1].cielova_ip, cielova_ip);

		if (strcmp(cielovy_port, "20") == 0 || strcmp(zdrojovy_port, "20") == 0 || strcmp(cielovy_port, "FTP-DATA\n") == 0 || strcmp(zdrojovy_port, "FTP-DATA\n") == 0) {
			lokal[0].pocet_ftp_datove++;
			strcpy(lokal[pocet_ramcov - 1].typ_protokolu, "FTP-DATA");
		}
		else if (strcmp(cielovy_port, "21") == 0 || strcmp(zdrojovy_port, "21") == 0 || strcmp(cielovy_port, "FTP-CONTROL\n") == 0 || strcmp(zdrojovy_port, "FTP-CONTROL\n") == 0) {
			lokal[0].pocet_ftp_riadiace++;
			strcpy(lokal[pocet_ramcov - 1].typ_protokolu, "FTP-CONTROL");
		}
		else if (strcmp(cielovy_port, "22") == 0 || strcmp(zdrojovy_port, "22") == 0 || strcmp(zdrojovy_port, "SSH\n") == 0 || strcmp(cielovy_port, "SSH\n") == 0) {
			lokal[0].pocet_ssh++;
			strcpy(lokal[pocet_ramcov - 1].typ_protokolu, "SSH");
		} 
		else if (strcmp(cielovy_port, "23") == 0 || strcmp(zdrojovy_port, "23") == 0 || strcmp(cielovy_port, "TELNET\n") == 0 || strcmp(zdrojovy_port, "TELNET\n") == 0) {
			lokal[0].pocet_telnet++;
			strcpy(lokal[pocet_ramcov - 1].typ_protokolu, "TELNET");
		}
		
		else if (strcmp(cielovy_port, "80") == 0 || strcmp(zdrojovy_port, "80") == 0 || strcmp(zdrojovy_port, "HTTP\n") == 0 || strcmp(cielovy_port, "HTTP\n") == 0) {
			lokal[0].pocet_http++;
			strcpy(lokal[pocet_ramcov - 1].typ_protokolu, "HTTP");
		}
		else if (strcmp(cielovy_port, "443") == 0 || strcmp(zdrojovy_port, "443") == 0 || strcmp(zdrojovy_port, "HTTPS\n") == 0 || strcmp(cielovy_port, "HTTPS\n") == 0) {
			lokal[0].pocet_https++;
			strcpy(lokal[pocet_ramcov - 1].typ_protokolu, "HTTPS");
		}

		*struktura = lokal;
	/*	int i = 0;
		while (lokal[0].pocet_ramcov_v_strukture > i) {
			printf("Poradove %d\n", lokal[i].poradove_cislo_v_ramci);
			printf("Typ %s\n", lokal[i].typ_protokolu);
			i++;
		}*/
		return 0;
	}
}


int vypis_tcp_komunikaciu(TCP_KOMUNIKACIA* struktura, RAMEC *ramce, u_char* data, char protokol_na_vypisanie) {
	char flag[3];
	int vypisana_nekompletna = 0;
	int pocet_ramcov_komunikacii = 0;
	char nazov_protokolu[PROTOCOL_BUFFER_SIZE];
	int i = 0, cislo_ramca = -1;
	int cislo_ramcov_v_komunikacii[1000];
	KOMPLETNA_KOMUNIKACIA* komplet = NULL;
	char zaciatocna_zdrojova_ip[GENERAL_BUFFER_SIZE], zaciatocna_cielova_ip[GENERAL_BUFFER_SIZE], aktualna_cielova_ip[GENERAL_BUFFER_SIZE];
	char aktualna_zdrojova_ip[GENERAL_BUFFER_SIZE];
	char zdrojovy_port1[GENERAL_BUFFER_SIZE], zdrojovy_port2[GENERAL_BUFFER_SIZE];
	char aktualny_zdroj_port1[GENERAL_BUFFER_SIZE], aktualny_zdroj_port2[GENERAL_BUFFER_SIZE], aktualny_ciel_port1[GENERAL_BUFFER_SIZE], aktualny_ciel_port2[GENERAL_BUFFER_SIZE];

	if (protokol_na_vypisanie == 'a')	strcpy(nazov_protokolu, "HTTP");
	else if (protokol_na_vypisanie == 'b') strcpy(nazov_protokolu, "HTTPS");
	else if (protokol_na_vypisanie == 'c') strcpy(nazov_protokolu, "TELNET");
	else if (protokol_na_vypisanie == 'd') strcpy(nazov_protokolu, "SSH");
	else if (protokol_na_vypisanie == 'e') strcpy(nazov_protokolu, "FTP-CONTROL");
	else if (protokol_na_vypisanie == 'f')  strcpy(nazov_protokolu, "FTP-DATA");
	else return 0;

	//fin , ack je 11		rst je 04		rst, ack je 14
	i = 0;
	while (i < struktura[0].pocet_ramcov_v_strukture) {
		pocet_ramcov_komunikacii = 0;

		if (strcmp(struktura[i].typ_protokolu, nazov_protokolu) == 0) {
			cislo_ramca = struktura[i].poradove_cislo_v_ramci;
			sprintf(flag, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[47]);

			if (strcmp(flag, "02") == 0) {	//hladat do konca suboru 12
				komplet = (KOMPLETNA_KOMUNIKACIA*)realloc(komplet, 1 * sizeof(KOMPLETNA_KOMUNIKACIA));
				komplet[0].cislo_v_ramci = cislo_ramca;

				sprintf(zdrojovy_port1, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[34]);
				sprintf(zdrojovy_port2, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[35]);
				sprintf(aktualny_zdroj_port1, "%.2x", ramce[cislo_ramca].smernik_na_data[34]);
				sprintf(aktualny_zdroj_port2, "%.2x", ramce[cislo_ramca].smernik_na_data[35]);
				sprintf(aktualny_ciel_port1, "%.2x", ramce[cislo_ramca].smernik_na_data[36]);
				sprintf(aktualny_ciel_port2, "%.2x", ramce[cislo_ramca].smernik_na_data[37]);
				sprintf(zaciatocna_zdrojova_ip, "%d.%d.%d.%d", ramce[cislo_ramca - 1].smernik_na_data[26], ramce[cislo_ramca - 1].smernik_na_data[27], ramce[cislo_ramca - 1].smernik_na_data[28],
					ramce[cislo_ramca - 1].smernik_na_data[29]);
				sprintf(zaciatocna_cielova_ip, "%d.%d.%d.%d", ramce[cislo_ramca - 1].smernik_na_data[30], ramce[cislo_ramca - 1].smernik_na_data[31], ramce[cislo_ramca - 1].smernik_na_data[32],
					ramce[cislo_ramca - 1].smernik_na_data[33]);
				
				int a = i; int posun = 0;
			//	a++;
				while (a < struktura[0].pocet_ramcov_v_strukture)
				{
					cislo_ramca = struktura[a].poradove_cislo_v_ramci;
					sprintf(aktualny_zdroj_port1, "%.2x", ramce[cislo_ramca].smernik_na_data[34]);
					sprintf(aktualny_zdroj_port2, "%.2x", ramce[cislo_ramca].smernik_na_data[35]);
					sprintf(aktualny_ciel_port1, "%.2x", ramce[cislo_ramca].smernik_na_data[36]);
					sprintf(aktualny_ciel_port2, "%.2x", ramce[cislo_ramca].smernik_na_data[37]);

					if ((strcmp(struktura[a].cielova_ip, zaciatocna_zdrojova_ip) == 0) && (strcmp(struktura[a].zdrojova_ip, zaciatocna_cielova_ip) == 0) ||
						(strcmp(struktura[a].cielova_ip, zaciatocna_cielova_ip) == 0) && (strcmp(struktura[a].zdrojova_ip, zaciatocna_zdrojova_ip) == 0)) {
						if (strcmp(struktura[a].typ_protokolu, nazov_protokolu) == 0)
							if ((strcmp(zdrojovy_port1, aktualny_zdroj_port1) == 0 && strcmp(zdrojovy_port2, aktualny_zdroj_port2) == 0) ||
								((strcmp(zdrojovy_port1, aktualny_ciel_port1) == 0 && strcmp(zdrojovy_port2, aktualny_ciel_port2) == 0)))
								sprintf(flag, "%.2x", ramce[cislo_ramca].smernik_na_data[47]); 
					}
					
					if (strcmp(flag, "12") == 0) {
						komplet = (KOMPLETNA_KOMUNIKACIA*)realloc(komplet, 2 * sizeof(KOMPLETNA_KOMUNIKACIA));
						komplet[1].cislo_v_ramci = cislo_ramca+1;
						break;
					}
					a++; posun++;
				}

				if (strcmp(flag, "12") == 0) {
					sprintf(zdrojovy_port1, "%.2x", ramce[cislo_ramca - 1 - posun].smernik_na_data[34]);
					sprintf(zdrojovy_port2, "%.2x", ramce[cislo_ramca - 1 - posun].smernik_na_data[35]);
					
					pocet_ramcov_komunikacii = 2;
					int j = a-posun;
					printf("zaciatok komunikacie\n");
					printf("Komunikacia zacina ramcom %d\n", struktura[j].poradove_cislo_v_ramci);

					sprintf(zaciatocna_zdrojova_ip, "%d.%d.%d.%d", ramce[cislo_ramca - 1 - posun].smernik_na_data[26], ramce[cislo_ramca - 1 - posun].smernik_na_data[27], ramce[cislo_ramca - 1-posun].smernik_na_data[28],
						ramce[cislo_ramca - 1-posun].smernik_na_data[29]);
					sprintf(zaciatocna_cielova_ip, "%d.%d.%d.%d", ramce[cislo_ramca - 1 - posun].smernik_na_data[30], ramce[cislo_ramca - 1 - posun].smernik_na_data[31], ramce[cislo_ramca - 1-posun].smernik_na_data[32],
						ramce[cislo_ramca - 1-posun].smernik_na_data[33]);
					//11 je fin, ack, 14 je rst ack
					while (j < struktura[0].pocet_ramcov_v_strukture) {
						sprintf(aktualny_zdroj_port1, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[34]);
						sprintf(aktualny_zdroj_port2, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[35]);
						sprintf(aktualny_ciel_port1, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[36]);
						sprintf(aktualny_ciel_port2, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[37]);

						if (((strcmp(zdrojovy_port1, aktualny_zdroj_port1) == 0 && strcmp(zdrojovy_port2, aktualny_zdroj_port2) == 0) ||
							((strcmp(zdrojovy_port1, aktualny_ciel_port1) == 0) && strcmp(zdrojovy_port2, aktualny_ciel_port2) == 0)) &&
							(strcmp(flag, "11") == 0) && ((strcmp(struktura[j].cielova_ip, zaciatocna_cielova_ip) == 0 || strcmp(struktura[j].cielova_ip, zaciatocna_zdrojova_ip) == 0) &&
								(strcmp(struktura[j].zdrojova_ip, zaciatocna_cielova_ip) == 0 || strcmp(struktura[j].zdrojova_ip, zaciatocna_zdrojova_ip) == 0))) break;

						if (((strcmp(zdrojovy_port1, aktualny_zdroj_port1) == 0 && strcmp(zdrojovy_port2, aktualny_zdroj_port2) == 0) ||
							((strcmp(zdrojovy_port1, aktualny_ciel_port1) == 0) && strcmp(zdrojovy_port2, aktualny_ciel_port2) == 0)) &&
							(strcmp(flag, "14") == 0) && ((strcmp(struktura[j].cielova_ip, zaciatocna_cielova_ip) == 0 || strcmp(struktura[j].cielova_ip, zaciatocna_zdrojova_ip) == 0) &&
								(strcmp(struktura[j].zdrojova_ip, zaciatocna_cielova_ip) == 0 || strcmp(struktura[j].zdrojova_ip, zaciatocna_zdrojova_ip) == 0))) break;

						if (strcmp(flag, "02") == 0 || (strcmp(flag, "12") == 0)) {
							j++;
							if (j + 1 < struktura[0].pocet_ramcov_v_strukture) {
								if (strcmp(struktura[j].typ_protokolu, nazov_protokolu) == 0)
									cislo_ramca = struktura[j].poradove_cislo_v_ramci;
								sprintf(flag, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[47]);
								continue;
							}
							else break;
						}
						if (strcmp(struktura[j].typ_protokolu, nazov_protokolu) == 0) {
							sprintf(aktualny_zdroj_port1, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[34]);
							sprintf(aktualny_zdroj_port2, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[35]);
							sprintf(aktualny_ciel_port1, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[36]);
							sprintf(aktualny_ciel_port2, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[37]);
							if (((strcmp(zdrojovy_port1, aktualny_zdroj_port1) == 0 && strcmp(zdrojovy_port2, aktualny_zdroj_port2) == 0) ||
								((strcmp(zdrojovy_port1, aktualny_ciel_port1) == 0 && strcmp(zdrojovy_port2, aktualny_ciel_port2) == 0))) &&
								(strcmp(struktura[j].cielova_ip, zaciatocna_cielova_ip) == 0 || strcmp(struktura[j].cielova_ip, zaciatocna_zdrojova_ip) == 0) &&
								(strcmp(struktura[j].zdrojova_ip, zaciatocna_cielova_ip) == 0 || strcmp(struktura[j].zdrojova_ip, zaciatocna_zdrojova_ip) == 0)) {
								pocet_ramcov_komunikacii++;
								komplet = (KOMPLETNA_KOMUNIKACIA*)realloc(komplet, pocet_ramcov_komunikacii * sizeof(KOMPLETNA_KOMUNIKACIA));
								komplet[pocet_ramcov_komunikacii - 1].cislo_v_ramci = cislo_ramca;
							}
						}
						j++;
						if (strcmp(struktura[j].typ_protokolu, nazov_protokolu) == 0)
							cislo_ramca = struktura[j].poradove_cislo_v_ramci;
						sprintf(flag, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[47]);
					}//koniec while	//ma ich byt 36
					//i je na ramci 51
					pocet_ramcov_komunikacii++;
					komplet = (KOMPLETNA_KOMUNIKACIA*)realloc(komplet, pocet_ramcov_komunikacii * sizeof(KOMPLETNA_KOMUNIKACIA));
					komplet[pocet_ramcov_komunikacii - 1].cislo_v_ramci = cislo_ramca;
					if (j + 1 < struktura[0].pocet_ramcov_v_strukture)
					{
						j++;
						cislo_ramca = struktura[j].poradove_cislo_v_ramci;
						sprintf(aktualny_zdroj_port1, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[34]);
						sprintf(aktualny_zdroj_port2, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[35]);
						sprintf(aktualny_ciel_port1, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[36]);
						sprintf(aktualny_ciel_port2, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[37]);
						sprintf(flag, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[47]);

						if (strcmp(struktura[j].typ_protokolu, nazov_protokolu) == 0)
							if ((strcmp(flag, "11") == 0) || (strcmp(flag, "10") == 0))
								if (((strcmp(struktura[j].cielova_ip, zaciatocna_cielova_ip) == 0 || strcmp(struktura[j].cielova_ip, zaciatocna_zdrojova_ip) == 0) &&
									(strcmp(struktura[j].zdrojova_ip, zaciatocna_cielova_ip) == 0 || strcmp(struktura[j].zdrojova_ip, zaciatocna_zdrojova_ip) == 0)))
									if (strcmp(aktualny_zdroj_port1, zdrojovy_port1) == 0)
										if (strcmp(aktualny_zdroj_port2, zdrojovy_port2) == 0) {
											j++; pocet_ramcov_komunikacii++; cislo_ramca = struktura[j].poradove_cislo_v_ramci;
											komplet = (KOMPLETNA_KOMUNIKACIA*)realloc(komplet, pocet_ramcov_komunikacii * sizeof(KOMPLETNA_KOMUNIKACIA));
											komplet[pocet_ramcov_komunikacii - 1].cislo_v_ramci = cislo_ramca;
										}

						sprintf(aktualny_zdroj_port1, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[34]);
						sprintf(aktualny_zdroj_port2, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[35]);
						sprintf(aktualny_ciel_port1, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[36]);
						sprintf(aktualny_ciel_port2, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[37]);
						//dat while co hlada rst
						if (strcmp(struktura[j].typ_protokolu, nazov_protokolu) == 0) 
							if (strcmp(aktualny_zdroj_port1, zdrojovy_port1) == 0 || strcmp(aktualny_ciel_port1, zdrojovy_port1) == 0)
								if ((strcmp(aktualny_zdroj_port2, zdrojovy_port2) == 0) || (strcmp(aktualny_ciel_port2, zdrojovy_port2) == 0)){
								cislo_ramca = struktura[j].poradove_cislo_v_ramci;
								sprintf(flag, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[47]);
								}
						

						sprintf(aktualny_zdroj_port1, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[34]);
						sprintf(aktualny_zdroj_port2, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[35]);
						sprintf(aktualny_ciel_port1, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[36]);
						sprintf(aktualny_ciel_port2, "%.2x", ramce[cislo_ramca - 1].smernik_na_data[37]);


						if ((strcmp(flag, "14") == 0) || (strcmp(flag, "11") == 0)) {
							pocet_ramcov_komunikacii++; j++;
							komplet = (KOMPLETNA_KOMUNIKACIA*)realloc(komplet, pocet_ramcov_komunikacii * sizeof(KOMPLETNA_KOMUNIKACIA));
							komplet[pocet_ramcov_komunikacii - 1].cislo_v_ramci = cislo_ramca;
						}
						else if ((strcmp(aktualny_zdroj_port1, zdrojovy_port1) == 0 && strcmp(aktualny_zdroj_port2, zdrojovy_port2) == 0) ||
							((strcmp(aktualny_ciel_port1, zdrojovy_port1) == 0) && (strcmp(aktualny_ciel_port2, zdrojovy_port2) == 0)) && strcmp(flag, "04") == 0) {
							pocet_ramcov_komunikacii++;
							komplet = (KOMPLETNA_KOMUNIKACIA*)realloc(komplet, pocet_ramcov_komunikacii * sizeof(KOMPLETNA_KOMUNIKACIA));
							komplet[pocet_ramcov_komunikacii - 1].cislo_v_ramci = cislo_ramca;
							printf("Komunikacia konci na ramci %d s poctom ramcov komunikacii %d\n", cislo_ramca, pocet_ramcov_komunikacii);
							int b = 0;

							while (b < pocet_ramcov_komunikacii) {
								printf("Cislo v ramci %d\n", komplet[b].cislo_v_ramci);
								b++;
							}
							i++;
							continue;
						}

						if (j < struktura[0].pocet_ramcov_v_strukture) {
							cislo_ramca = struktura[j].poradove_cislo_v_ramci;
							sprintf(flag, "%.2x", ramce[cislo_ramca - 1 - posun].smernik_na_data[47]);
						}

						else {
							printf("Komunikacia konci na ramci %d s poctom ramcov komunikacii %d\n", cislo_ramca, pocet_ramcov_komunikacii);
							memset(flag, 0, 3);
						}
						//tu bol 04
						if (strcmp(flag, "10") == 0 || strcmp(flag, "04") == 0) {		//hladam rst do konca suboru
							pocet_ramcov_komunikacii++;
							komplet = (KOMPLETNA_KOMUNIKACIA*)realloc(komplet, pocet_ramcov_komunikacii * sizeof(KOMPLETNA_KOMUNIKACIA));
							komplet[pocet_ramcov_komunikacii - 1].cislo_v_ramci = cislo_ramca;
							int o = j;
							int nove_cislo_ramca;
							while (o < struktura[0].pocet_ramcov_v_strukture) {
								nove_cislo_ramca = struktura[o].poradove_cislo_v_ramci;
								sprintf(aktualny_zdroj_port1, "%.2x", ramce[nove_cislo_ramca - 1].smernik_na_data[34]);
								sprintf(aktualny_zdroj_port2, "%.2x", ramce[nove_cislo_ramca - 1].smernik_na_data[35]);
								sprintf(aktualny_ciel_port1, "%.2x", ramce[nove_cislo_ramca - 1].smernik_na_data[36]);
								sprintf(aktualny_ciel_port2, "%.2x", ramce[nove_cislo_ramca - 1].smernik_na_data[37]);
								sprintf(flag, "%.2x", ramce[nove_cislo_ramca - 1].smernik_na_data[47]);

								if ((strcmp(struktura[0].typ_protokolu, nazov_protokolu) == 0) && (strcmp(flag, "04") == 0))
									if ((strcmp(struktura[o].cielova_ip, zaciatocna_cielova_ip) == 0 || strcmp(struktura[o].cielova_ip, zaciatocna_zdrojova_ip) == 0) &&
										(strcmp(struktura[o].zdrojova_ip, zaciatocna_cielova_ip) == 0 || strcmp(struktura[o].zdrojova_ip, zaciatocna_zdrojova_ip) == 0))
										if((strcmp(aktualny_zdroj_port1, zdrojovy_port1) == 0 && strcmp(aktualny_zdroj_port2, zdrojovy_port2) == 0) ||
											((strcmp(aktualny_ciel_port1, zdrojovy_port1) == 0) && (strcmp(aktualny_ciel_port2, zdrojovy_port2) == 0)))
									{
									
									printf("Komunikacia konci na ramci %d s poctom ramcov komunikacii %d\n", nove_cislo_ramca, pocet_ramcov_komunikacii);
									break;
								}o++;
							}
							if(o == struktura[0].pocet_ramcov_v_strukture)
								printf("Komunikacia konci na ramci %d s poctom ramcov komunikacii %d\n", cislo_ramca, pocet_ramcov_komunikacii);
						}
					}
					else printf("Neukoncena komunikacia\n");
				}
			}
		} 
		int b = 0;

			while (b < pocet_ramcov_komunikacii) {
				printf("Cislo v ramci %d\n", komplet[b].cislo_v_ramci);
				b++;
			}			
		i++;
	}
}

int vypis_linkovej_vrstvy(int poradove_cislo, RAMEC* ramce, u_char* data, FILE* subor_s_protokolmi_a_portmi, FILE* vystupny_subor, char vnoreny_protokol[], char transport_protokol[],
	char nazov_zdrojoveho_portu[], char nazov_cieloveho_portu[], char cislo_zdroj_portu[], char cislo_ciel_portu[], int uloha) {
	int rv = GENERAL_ERROR;
	//nazov_zdrojoveho_portu,
	//nazov_cieloveho_portu, cislo_zdrojoveho_portu, cislo_cieloveho_portu);
	char transportny_protokol[PROTOCOL_BUFFER_SIZE];
	char cielovy_port[GENERAL_BUFFER_SIZE], zdrojovy_port[GENERAL_BUFFER_SIZE];
	char cislo_cieloveho_portu[GENERAL_BUFFER_SIZE], cislo_zdrojoveho_portu[GENERAL_BUFFER_SIZE];

	if (uloha != 1) {
		memset(vnoreny_protokol, 0, sizeof(vnoreny_protokol));
		memset(nazov_zdrojoveho_portu, 0, sizeof(nazov_zdrojoveho_portu));
		memset(nazov_cieloveho_portu, 0, sizeof(nazov_cieloveho_portu));
		memset(cislo_zdroj_portu, 0, sizeof(cislo_zdroj_portu));
		memset(cislo_ciel_portu, 0, sizeof(cislo_ciel_portu));
	}


	if (data[12] >= 06) {
	
		if(uloha != 4 && uloha != 5) fprintf(vystupny_subor, "Ethernet II\n");
		if(uloha != 1) {
			char typ_ramca[GENERAL_BUFFER_SIZE] = "EthernetII";
			zisti_ethernet2_protokol(data, subor_s_protokolmi_a_portmi, vnoreny_protokol, PROTOCOL_BUFFER_SIZE, typ_ramca, uloha);
			if (uloha == 4) return 0;
			if (vnoreny_protokol != 0 && uloha != 5) fprintf(vystupny_subor, "%s", vnoreny_protokol);
			if (vnoreny_protokol != NULL && strcmp(vnoreny_protokol, "IPv4\n") == 0)
				zisti_transportny_protokol(data, subor_s_protokolmi_a_portmi, &transportny_protokol, uloha);
			if (transportny_protokol != NULL && uloha != 1 && uloha != 5) fprintf(vystupny_subor, "%s\n", transportny_protokol);
			strcpy(transport_protokol, transportny_protokol);
			if (uloha == 5) return 0;
			if (strcmp(transportny_protokol, "TCP") == 0) {
				vypis_tcp_portov(data, subor_s_protokolmi_a_portmi, vystupny_subor, transportny_protokol, cielovy_port, cislo_cieloveho_portu, zdrojovy_port, cislo_zdrojoveho_portu, uloha);
				strcpy(nazov_zdrojoveho_portu, zdrojovy_port);
				strcpy(nazov_cieloveho_portu, cielovy_port);
				strcpy(cislo_zdroj_portu, cislo_zdrojoveho_portu);
				strcpy(cislo_ciel_portu, cislo_cieloveho_portu);
			}

			else if (strcmp(transportny_protokol, "UDP") == 0) vypis_udp_portov(data, subor_s_protokolmi_a_portmi, vystupny_subor, transportny_protokol, cielovy_port, zdrojovy_port, uloha);
		}
	}
	//	if (strcmp(cielovy_port, "TFTP\n") == 0) vypis_tftp_komunikaciu(poradove_cislo, ramce, data);


	else if (data[14] == 255) {
		if (uloha != 4 && uloha != 5) fprintf(vystupny_subor, "IEEE 802.3 - Raw\n");
				if (uloha != 1 && uloha != 4) fprintf(vystupny_subor, "IPx\n");
			
		rv = SUCCESS;
		return rv;
	}

	else if (data[14] == 170) {
		if (uloha != 4 && uloha != 5)	fprintf(vystupny_subor, "Ramec %d\n", poradove_cislo);
			if (uloha != 1 && uloha != 4 && uloha != 5)
			{
				fprintf(vystupny_subor, "IEEE 802.3 so SNAP\n");
				char typ_ramca[GENERAL_BUFFER_SIZE] = "Snap";
				zisti_ethernet2_protokol(data, subor_s_protokolmi_a_portmi, vnoreny_protokol, PROTOCOL_BUFFER_SIZE, typ_ramca, uloha);
				if (vnoreny_protokol != 0) fprintf(vystupny_subor, "%s", vnoreny_protokol);
			}
				rv = SUCCESS;
				return rv;	
	}

	else {
			
		if (uloha != 4 && uloha != 5)	fprintf(vystupny_subor, "Ramec %d\n", poradove_cislo);
		if (uloha != 1 && uloha != 4 && uloha != 5) {
			fprintf(vystupny_subor, "IEEE 802.3 s LLC\n");

			zisti_LLC_protokol(data, subor_s_protokolmi_a_portmi, vnoreny_protokol, PROTOCOL_BUFFER_SIZE, uloha);
			if (vnoreny_protokol != 0) fprintf(vystupny_subor, "%s", vnoreny_protokol);
		}
		
		rv = SUCCESS;
		return rv;
	}
}


int vypis_dlzky_ramca(int dlzka, FILE* vystupny_subor) {
	fprintf(vystupny_subor, "Dlzka ramca poskytnuta pcap API - %d B\n", dlzka);
	if (64 - dlzka > 4) fprintf(vystupny_subor, "Dlzka ramca prenasaneho po mediu - 64 B\n");
	else fprintf(vystupny_subor, "Dlzka ramca prenasaneho po mediu - %d B\n", dlzka + 4);
	return 0;
}


int alokuj_ramec(RAMEC** ramce, int j, struct pcap_pkthdr* hlavicka, u_char* data) {
	RAMEC* ramec_lokal = *ramce;
	ramec_lokal = (RAMEC*)realloc(ramec_lokal, j * sizeof(RAMEC));
	ramec_lokal[j - 1].pcap_hlavicka = *hlavicka;
	ramec_lokal[j - 1].smernik_na_data = (u_char*)calloc(hlavicka->caplen, sizeof(u_char));
	memcpy(ramec_lokal[j - 1].smernik_na_data, data, hlavicka->caplen);

	*ramce = ramec_lokal;
	return 0;
}

int alokuj_strukturu_pre_ip(IP_ADRESY** struktura_ip_adries, RAMEC* ramce, u_char* data, int j, FILE* subor_s_portmi_a_protokolmi) {
	int i = 0;
	char protokol[PROTOCOL_BUFFER_SIZE];
	char ip[GENERAL_BUFFER_SIZE] = { 0 };
	char linkova_vrstva[GENERAL_BUFFER_SIZE];
	int pocet_ip_adries = 0;
	char vnoreny_protokol[PROTOCOL_BUFFER_SIZE];

	memset(protokol, 0, PROTOCOL_BUFFER_SIZE);

	if (ramce[j-1].smernik_na_data[12] >= 06 && *struktura_ip_adries == NULL)  {
		strcpy(linkova_vrstva, "EthernetII");
		zisti_ethernet2_protokol(ramce[j - 1].smernik_na_data, subor_s_portmi_a_protokolmi, &protokol, PROTOCOL_BUFFER_SIZE, linkova_vrstva);
		if (strcmp(protokol, "IPv4\n") == 0) {
			snprintf(ip, GENERAL_BUFFER_SIZE, "%d.%d.%d.%d", ramce[j - 1].smernik_na_data[30], ramce[j - 1].smernik_na_data[31],
				ramce[j - 1].smernik_na_data[32], ramce[j - 1].smernik_na_data[33]);
			pocet_ip_adries = 1; 
			IP_ADRESY* adresy_lokal = *struktura_ip_adries;
			adresy_lokal = (IP_ADRESY*)realloc(adresy_lokal, pocet_ip_adries * sizeof(IP_ADRESY));
			adresy_lokal->pocet_ip_adries = 1;
			strcpy(adresy_lokal->ip_adresa, ip);
			adresy_lokal->pocet_paketov = 1;
			*struktura_ip_adries = adresy_lokal;
			return 0;
		}
	}

	else if (ramce[j - 1].smernik_na_data[12] >= 06) {
		strcpy(linkova_vrstva, "EthernetII");
		zisti_ethernet2_protokol(ramce[j - 1].smernik_na_data, subor_s_portmi_a_protokolmi, protokol, PROTOCOL_BUFFER_SIZE, linkova_vrstva);
		if (strcmp(protokol, "IPv4\n") == 0)
			snprintf(ip, GENERAL_BUFFER_SIZE, "%d.%d.%d.%d", ramce[j - 1].smernik_na_data[30], ramce[j - 1].smernik_na_data[31],
				ramce[j - 1].smernik_na_data[32], ramce[j - 1].smernik_na_data[33]);
		IP_ADRESY* adresy_lokal = *struktura_ip_adries;
	
		pocet_ip_adries = adresy_lokal[0].pocet_ip_adries;

		while (i < pocet_ip_adries) {
			if (strcmp(adresy_lokal[i].ip_adresa, ip, 15) == 0) {
				adresy_lokal[i].pocet_paketov++;
				*struktura_ip_adries = adresy_lokal;
				return 0;
			}
			i++;
		}

		int pocet = adresy_lokal[0].pocet_ip_adries;
		pocet++;

		adresy_lokal = (IP_ADRESY*)realloc(adresy_lokal, pocet * sizeof(IP_ADRESY));

		strcpy(adresy_lokal[pocet_ip_adries].ip_adresa, ip);
		adresy_lokal[pocet-1].pocet_paketov = 1; 
		adresy_lokal[0].pocet_ip_adries++;
	//	printf("Pocet ip adries %d\n", adresy_lokal[0].pocet_ip_adries);
		*struktura_ip_adries = adresy_lokal;
		return 0;
	}
}

int icmp_komunikacia(ICMP_KOMUNIKACIA* struktura_icmp_komunikacii, FILE *vystup, FILE *subor_s_portmi_a_protokolmi, RAMEC* ramce){
	int pocet_ramcov_v_strukture = struktura_icmp_komunikacii[0].pocet_ramcov_v_strukture;
	int j = 0, k = 1, pocet_komunikacii = 0;
	char ip_cielova[GENERAL_BUFFER_SIZE], ip_zdrojova[GENERAL_BUFFER_SIZE];

	while (j < pocet_ramcov_v_strukture) {
		if (strcmp(struktura_icmp_komunikacii[j].typ, "echo") == 0) {
			while ((strcmp(struktura_icmp_komunikacii[k].typ, "echo") == 0)) {
				k++;
			}

			fprintf(vystup, "Komunikacia c. %d\n", ++pocet_komunikacii);
			fprintf(vystup, "Ramec s echo: %d\tRamec s odpovedou: %d\n", struktura_icmp_komunikacii[j].cislo_ramca, struktura_icmp_komunikacii[j + 1].cislo_ramca);

			fprintf(vystup, "Ramec s echo\n");
			vypis_dlzky_ramca(ramce[j].pcap_hlavicka.caplen, vystup);
			vypis_linkovej_vrstvy(j + 1, ramce, ramce[j].smernik_na_data, subor_s_portmi_a_protokolmi, vystup, 0, 0, 0, 0, 0, 0, 1);
			vypis_MAC_adresy(ramce[j].smernik_na_data, vystup);
			fprintf(vystup, "\n");
			vypis_bajty(ramce[j].smernik_na_data, ramce[j - 1].pcap_hlavicka.caplen, vystup);
			fprintf(vystup, "\n\n");

			fprintf(vystup, "Ramec s odpovedou\n");
			vypis_dlzky_ramca(ramce[j+1].pcap_hlavicka.caplen, vystup);
			vypis_linkovej_vrstvy(j + 2, ramce, ramce[j+1].smernik_na_data, subor_s_portmi_a_protokolmi, vystup, 0, 0, 0, 0, 0, 0, 1);
			vypis_MAC_adresy(ramce[j+1].smernik_na_data, vystup);
			fprintf(vystup, "\n");
			vypis_bajty(ramce[j+1].smernik_na_data, ramce[j].pcap_hlavicka.caplen, vystup);
			fprintf(vystup, "\n\n");

			fprintf(vystup, "Typ odpovede: %s\n", struktura_icmp_komunikacii[k].typ);
		}
		j++; k = j + 1;
	}
}

int alokuj_icmp_strukturu(ICMP_KOMUNIKACIA **struktura_icmp_komunikacii, RAMEC* ramce, int poradove_cislo) {
	char type[GENERAL_BUFFER_SIZE];
	int pocet_icmp_ramcov = 0;
	ICMP_KOMUNIKACIA* icmp_lokal = *struktura_icmp_komunikacii;
	
	sprintf(type, "%.2x", ramce[poradove_cislo-1].smernik_na_data[34]);

	if (icmp_lokal == NULL) {
		icmp_lokal = (ICMP_KOMUNIKACIA*)realloc(icmp_lokal, 1 * sizeof(ICMP_KOMUNIKACIA));
		icmp_lokal[0].cislo_ramca = poradove_cislo;
		icmp_lokal[0].pocet_ramcov_v_strukture = 1;
		if (strcmp(type, "00") == 0) strcpy(icmp_lokal[0].typ, "echo reply");
		else if (strcmp(type, "03") == 0) 	strcpy(icmp_lokal[0].typ, "destination unreachable");
		else if (strcmp(type, "05") == 0) 	strcpy(icmp_lokal[0].typ, "redirect");
		else if (strcmp(type, "08") == 0) 	strcpy(icmp_lokal[0].typ, "echo");
		else if (strcmp(type, "09") == 0) 	strcpy(icmp_lokal[0].typ, "router advertisement");
		else if (strcmp(type, "0a") == 0) 	strcpy(icmp_lokal[0].typ, "router selection");
		else if (strcmp(type, "0b") == 0) 	strcpy(icmp_lokal[0].typ, "time exceeded");
		else if (strcmp(type, "0c") == 0) 	strcpy(icmp_lokal[0].typ, "parameter problem");
		else if (strcmp(type, "0d") == 0) 	strcpy(icmp_lokal[0].typ, "timestamp");
		else if (strcmp(type, "0e") == 0) 	strcpy(icmp_lokal[0].typ, "timestamp reply");
		else if (strcmp(type, "0f") == 0) 	strcpy(icmp_lokal[0].typ, "information request");
		else if (strcmp(type, "10") == 0) 	strcpy(icmp_lokal[0].typ, "information reply");
		else if (strcmp(type, "11") == 0) 	strcpy(icmp_lokal[0].typ, "address mask request");
		else if (strcmp(type, "12") == 0) 	strcpy(icmp_lokal[0].typ, "adress mask reply");
		else if (strcmp(type, "1e") == 0) 	strcpy(icmp_lokal[0].typ, "traceroute");
		else strcpy(icmp_lokal[0].typ, "-1");
		*struktura_icmp_komunikacii = icmp_lokal;
		return 0;
	}

	else {
		icmp_lokal[0].pocet_ramcov_v_strukture++;
		pocet_icmp_ramcov = icmp_lokal[0].pocet_ramcov_v_strukture;
		icmp_lokal = (ARP_KOMUNIKACIA*)realloc(icmp_lokal, pocet_icmp_ramcov * sizeof(ARP_KOMUNIKACIA));
		icmp_lokal[pocet_icmp_ramcov-1].cislo_ramca = poradove_cislo;
		if (strcmp(type, "00") == 0) strcpy(icmp_lokal[pocet_icmp_ramcov - 1].typ, "echo reply");
		else if (strcmp(type, "03") == 0) 	strcpy(icmp_lokal[pocet_icmp_ramcov - 1].typ, "destination unreachable");
		else if (strcmp(type, "05") == 0) 	strcpy(icmp_lokal[pocet_icmp_ramcov - 1].typ, "redirect");
		else if (strcmp(type, "08") == 0) 	strcpy(icmp_lokal[pocet_icmp_ramcov - 1].typ, "echo");
		else if (strcmp(type, "09") == 0) 	strcpy(icmp_lokal[pocet_icmp_ramcov - 1].typ, "router advertisement");
		else if (strcmp(type, "0a") == 0) 	strcpy(icmp_lokal[pocet_icmp_ramcov - 1].typ, "router selection");
		else if (strcmp(type, "0b") == 0) 	strcpy(icmp_lokal[pocet_icmp_ramcov - 1].typ, "time exceeded");
		else if (strcmp(type, "0c") == 0) 	strcpy(icmp_lokal[pocet_icmp_ramcov - 1].typ, "parameter problem");
		else if (strcmp(type, "0d") == 0) 	strcpy(icmp_lokal[pocet_icmp_ramcov - 1].typ, "timestamp");
		else if (strcmp(type, "0e") == 0) 	strcpy(icmp_lokal[pocet_icmp_ramcov - 1].typ, "timestamp reply");
		else if (strcmp(type, "0f") == 0) 	strcpy(icmp_lokal[pocet_icmp_ramcov - 1].typ, "information request");
		else if (strcmp(type, "10") == 0) 	strcpy(icmp_lokal[pocet_icmp_ramcov - 1].typ, "information reply");
		else if (strcmp(type, "11") == 0) 	strcpy(icmp_lokal[pocet_icmp_ramcov - 1].typ, "address mask request");
		else if (strcmp(type, "12") == 0) 	strcpy(icmp_lokal[pocet_icmp_ramcov - 1].typ, "adress mask reply");
		else if (strcmp(type, "1e") == 0) 	strcpy(icmp_lokal[pocet_icmp_ramcov - 1].typ, "traceroute");
		else strcpy(icmp_lokal[pocet_icmp_ramcov - 1].typ, "-1");
		*struktura_icmp_komunikacii = icmp_lokal;
		return 0;
	}
}

int alokuj_arp_strukturu(ARP_KOMUNIKACIA** struktura_arp_komunikacii, RAMEC* ramce, int poradove_cislo_ramca) {
	int pocet_arp_ramcov;
	ARP_KOMUNIKACIA* arp_lokal = *struktura_arp_komunikacii;
	char opcode_ramca[3];
	int i = poradove_cislo_ramca - 1;
	int pocet_requestov_bez_reply = 0;
	sprintf(opcode_ramca, "%.2x", ramce[poradove_cislo_ramca - 1].smernik_na_data[21]);

	if (arp_lokal ==  NULL) {
		arp_lokal = (ARP_KOMUNIKACIA*)realloc(arp_lokal, 1 * sizeof(ARP_KOMUNIKACIA));
		arp_lokal[0].cislo_ramca = poradove_cislo_ramca;
		arp_lokal[0].pocet_ramcov = 1;
		sprintf(arp_lokal[0].zdrojova_ip, "%d.%d.%d.%d", ramce[i].smernik_na_data[28], ramce[i].smernik_na_data[29], ramce[i].smernik_na_data[30], ramce[i].smernik_na_data[31]);
		sprintf(arp_lokal[0].cielova_ip, "%d.%d.%d.%d", ramce[i].smernik_na_data[38], ramce[i].smernik_na_data[39], ramce[i].smernik_na_data[40], ramce[i].smernik_na_data[41]);
		sprintf(arp_lokal[0].zdrojova_mac, "%.2x %.2x %.2x %.2x %.2x %.2x", ramce[i].smernik_na_data[6], ramce[i].smernik_na_data[7], ramce[i].smernik_na_data[8], ramce[i].smernik_na_data[9],
			ramce[i].smernik_na_data[10], ramce[i].smernik_na_data[11]);
		strcpy(arp_lokal[0].opcode, opcode_ramca);

		if (strcmp(arp_lokal[0].opcode, "02") == 0) {
			arp_lokal[0].sparovany_reply = 0;
			arp_lokal[0].sparovany_request = NULL;
			strcpy(arp_lokal[0].typ, "reply");
			arp_lokal[0].pocet_reply_bez_request = 1;
		}

		else {
			arp_lokal[0].sparovany_request = 0;
			arp_lokal[0].sparovany_reply = NULL;
			strcpy(arp_lokal[0].typ, "request");
			arp_lokal[0].pocet_requestov_bez_reply = 1;
		}
		*struktura_arp_komunikacii = arp_lokal;
		return 0;
	}

	else {
		arp_lokal[0].pocet_ramcov++;
		pocet_arp_ramcov = arp_lokal[0].pocet_ramcov;
		arp_lokal = (ARP_KOMUNIKACIA*)realloc(arp_lokal, pocet_arp_ramcov*sizeof(ARP_KOMUNIKACIA));
		strcpy(arp_lokal[pocet_arp_ramcov-1].opcode, opcode_ramca);
		sprintf(arp_lokal[pocet_arp_ramcov - 1].zdrojova_ip, "%d.%d.%d.%d", ramce[i].smernik_na_data[28], ramce[i].smernik_na_data[29], ramce[i].smernik_na_data[30], ramce[i].smernik_na_data[31]);
		sprintf(arp_lokal[pocet_arp_ramcov - 1].cielova_ip, "%d.%d.%d.%d", ramce[i].smernik_na_data[38], ramce[i].smernik_na_data[39], ramce[i].smernik_na_data[40], ramce[i].smernik_na_data[41]);
		sprintf(arp_lokal[pocet_arp_ramcov - 1].zdrojova_mac, "%.2x %.2x %.2x %.2x %.2x %.2x", ramce[i].smernik_na_data[6], ramce[i].smernik_na_data[7], ramce[i].smernik_na_data[8], ramce[i].smernik_na_data[9],
			ramce[i].smernik_na_data[10], ramce[i].smernik_na_data[11]);
		arp_lokal[pocet_arp_ramcov - 1].cislo_ramca = poradove_cislo_ramca;

		if (strcmp(arp_lokal[pocet_arp_ramcov-1].opcode, "02") == 0)	{
			arp_lokal[pocet_arp_ramcov - 1].sparovany_reply = 0;
			arp_lokal[pocet_arp_ramcov - 1].sparovany_request = NULL;
			strcpy(arp_lokal[pocet_arp_ramcov - 1].typ, "reply");
			arp_lokal[0].pocet_reply_bez_request++;
		}

		else {
			arp_lokal[pocet_arp_ramcov - 1].sparovany_request = 0;
			arp_lokal[pocet_arp_ramcov - 1].sparovany_reply = NULL;
			strcpy(arp_lokal[pocet_arp_ramcov - 1].typ, "request");
			arp_lokal[0].pocet_requestov_bez_reply++;
		}
		*struktura_arp_komunikacii = arp_lokal;
		return 0;
	}
}

int vypis_ip_adresy(IP_ADRESY* struktura_ip_adries, FILE *vystupny_subor) {
	int i = 0;
	int max = -1;
	char adresa_s_max_paketmi[GENERAL_BUFFER_SIZE] = { 0 };
	fprintf(vystupny_subor, "IP adresy vysielajucich uzlov:\n");

	while (i < struktura_ip_adries[0].pocet_ip_adries) {
		fprintf(vystupny_subor, "%s\n", struktura_ip_adries[i].ip_adresa);
		if (max < struktura_ip_adries[i].pocet_paketov) {
			max = struktura_ip_adries[i].pocet_paketov;
			strcpy(adresa_s_max_paketmi, struktura_ip_adries[i].ip_adresa);
		}
		i++;
	}

	fprintf(vystupny_subor, "Adresa uzla s najvacsim poctom prijatych paketov %s \t %d\n", adresa_s_max_paketmi, max);
	return 0;
}


int main() {
	char chyba[PCAP_ERRBUF_SIZE];
	u_char* smernik_na_data = NULL;
	struct pcap_pkthdr* hlavicky = NULL;
	pcap_t* pcap_subor = NULL;
	RAMEC* ramce = NULL;
	IP_ADRESY* adresy = NULL;
	ARP_KOMUNIKACIA* struktura_arp_komunikacii = NULL;
	ICMP_KOMUNIKACIA* struktura_icmp_komunikacii = NULL;
	TCP_KOMUNIKACIA* struktura_tcp_komunikacii = NULL;
	FILE* subor_s_portmi_a_protokolmi;
	FILE* vystupny_subor;
	int j = 1;
	int pocet_ramcov = 0;
	char cesta_k_suboru_na_analyzu[GENERAL_BUFFER_SIZE];
	int pocet_ip_adries = 0;
	char linkova_vrstva[GENERAL_BUFFER_SIZE];
	char vnoreny_protokol[PROTOCOL_BUFFER_SIZE];
	char transportny_protokol[PROTOCOL_BUFFER_SIZE];
	char nazov_cieloveho_portu[GENERAL_BUFFER_SIZE], nazov_zdrojoveho_portu[GENERAL_BUFFER_SIZE];
	char cislo_zdrojoveho_portu[GENERAL_BUFFER_SIZE], cislo_cieloveho_portu[GENERAL_BUFFER_SIZE];
	char protokol_na_vypisanie = 0;
	char vypis_uloh[GENERAL_BUFFER_SIZE];
	int uloha = -1;
	
	vystupny_subor = fopen("vystup.txt", "w");
	if (NULL == vystupny_subor) {
		printf("Neotvoreny vystupny subor\n");
		return 0;
	}

	subor_s_portmi_a_protokolmi = fopen("cisla.txt", "r");
	if (NULL == subor_s_portmi_a_protokolmi) {
		printf("Neotvoreny subor s cislami portov a protokolov\n");
		return 0;
	}
	
	printf("Zadajte cestu k suboru na analyzu alebo napiste koniec pre ukoncenie\n");
	scanf("%s", cesta_k_suboru_na_analyzu);

	while (strcmp(cesta_k_suboru_na_analyzu, "koniec") != 0) {
		if ((pcap_subor = pcap_open_offline
		(cesta_k_suboru_na_analyzu, chyba)) == NULL)
			printf("Chyba %s\n", chyba);

		else {
			while (pcap_next_ex(pcap_subor, &hlavicky, &smernik_na_data) == 1) {
				pocet_ramcov++;
				alokuj_ramec(&ramce, pocet_ramcov, hlavicky, smernik_na_data);
			}

			printf("Zadajte cislo ulohy, ktoru chcete vypisat\n");
			
				scanf("%d", &uloha);
				if (uloha == 1) {
					fprintf(vystupny_subor, "Vypisujem subor s cestou: %s\n\n", cesta_k_suboru_na_analyzu);
					j = 1;
					while (j <= pocet_ramcov) {
						fprintf(vystupny_subor, "Ramec %d\n", j);
						vypis_dlzky_ramca(ramce[j - 1].pcap_hlavicka.caplen, vystupny_subor);
						vypis_linkovej_vrstvy(j, ramce, ramce[j - 1].smernik_na_data, subor_s_portmi_a_protokolmi, vystupny_subor, 0, 0, 0, 0, 0, 0, 1);
						//if (strcmp(vnoreny_protokol, "ARP\n") == 0) alokuj_arp_strukturu(&struktura_arp_komunikacii, ramce, j);
					//	if ((strcmp(vnoreny_protokol, "IPv4\n") == 0) && (strcmp(transportny_protokol, "ICMP") == 0))
						//	alokuj_icmp_strukturu(&struktura_icmp_komunikacii, ramce, j);
						vypis_MAC_adresy(ramce[j - 1].smernik_na_data, vystupny_subor);
						fprintf(vystupny_subor, "\n");
						vypis_bajty(ramce[j - 1].smernik_na_data, ramce[j - 1].pcap_hlavicka.caplen, vystupny_subor);
						fprintf(vystupny_subor, "\n\n\n");
						j++;
					}
				}
				if (uloha == 2) {
					fprintf(vystupny_subor, "Vypisujem subor s cestou: %s\n\n", cesta_k_suboru_na_analyzu);
					j = 1;
					while (j <= pocet_ramcov) {	
					fprintf(vystupny_subor, "Ramec %d\n", j);
					vypis_dlzky_ramca(ramce[j - 1].pcap_hlavicka.caplen, vystupny_subor);
					vypis_linkovej_vrstvy(pocet_ramcov, ramce, ramce[j - 1].smernik_na_data, subor_s_portmi_a_protokolmi, vystupny_subor, vnoreny_protokol, transportny_protokol, nazov_zdrojoveho_portu,
						nazov_cieloveho_portu, cislo_zdrojoveho_portu, cislo_cieloveho_portu, 2);
					vypis_MAC_adresy(ramce[j - 1].smernik_na_data, vystupny_subor);
					fprintf(vystupny_subor, "\n");
					vypis_bajty(ramce[j - 1].smernik_na_data, ramce[j - 1].pcap_hlavicka.caplen, vystupny_subor);
					fprintf(vystupny_subor, "\n\n\n");
					j++;
					}
				}
				if (uloha == 3) {
					j = 1;
					while (j <= pocet_ramcov) {
						fprintf(vystupny_subor, "Ramec %d\n", j);
						vypis_dlzky_ramca(ramce[j - 1].pcap_hlavicka.caplen, vystupny_subor);
						alokuj_strukturu_pre_ip(&adresy, ramce, ramce[j - 1].smernik_na_data, j, subor_s_portmi_a_protokolmi, vystupny_subor);

					//	if (strcmp(vnoreny_protokol, "ARP\n") == 0) alokuj_arp_strukturu(&struktura_arp_komunikacii, ramce, j);
					//	if ((strcmp(vnoreny_protokol, "IPv4\n") == 0) && (strcmp(transportny_protokol, "ICMP") == 0))
						//	alokuj_icmp_strukturu(&struktura_icmp_komunikacii, ramce, j);
						vypis_MAC_adresy(ramce[j - 1].smernik_na_data, vystupny_subor);
						fprintf(vystupny_subor, "\n");
						vypis_bajty(ramce[j - 1].smernik_na_data, ramce[j - 1].pcap_hlavicka.caplen, vystupny_subor);
						fprintf(vystupny_subor, "\n\n\n");
						j++;
					}
					vypis_ip_adresy(adresy, vystupny_subor);
				}

				if (uloha == 4) {
					printf("Zadajte protokol, ktoreho komunikaciu chcete vypisat:\n");
					printf("a pre HTTP\t b pre HTTPS\t\t c pre TELNET\nd pre SSH\t e pre FTP riadiace\t f pre FTP datove\ng pre TFTP\t h pre ICMP\t i pre ARP\n");
					scanf(" %c", &protokol_na_vypisanie);
					if (protokol_na_vypisanie == 'a' || protokol_na_vypisanie == 'b' || protokol_na_vypisanie == 'c' || protokol_na_vypisanie == 'd' || protokol_na_vypisanie == 'e' ||
						protokol_na_vypisanie == 'f') 			vypis_tcp_komunikaciu(struktura_tcp_komunikacii, ramce, ramce->smernik_na_data, protokol_na_vypisanie);
					else if (protokol_na_vypisanie == 'g') {


						vypis_tftp_komunikaciu(1, ramce, ramce->smernik_na_data);
					}//ciel musi byt tftp
					else if (protokol_na_vypisanie == 'h') {
						j = 1;
						while (j <= pocet_ramcov) {
							vypis_linkovej_vrstvy(j, ramce, ramce[j - 1].smernik_na_data, subor_s_portmi_a_protokolmi, vystupny_subor, vnoreny_protokol, transportny_protokol, nazov_zdrojoveho_portu,
								nazov_cieloveho_portu, cislo_zdrojoveho_portu, cislo_cieloveho_portu, 5);
													if ((strcmp(vnoreny_protokol, "IPv4\n") == 0) && (strcmp(transportny_protokol, "ICMP") == 0))
									alokuj_icmp_strukturu(&struktura_icmp_komunikacii, ramce, j);
													j++;
						}
						icmp_komunikacia(struktura_icmp_komunikacii, vystupny_subor, subor_s_portmi_a_protokolmi, ramce);
					}
					else if (protokol_na_vypisanie == 'i') {
						int a = 1;
						while (a <= pocet_ramcov) {
							vypis_linkovej_vrstvy(a, ramce, ramce[a - 1].smernik_na_data, subor_s_portmi_a_protokolmi, vystupny_subor, vnoreny_protokol, transportny_protokol, nazov_zdrojoveho_portu,
								nazov_cieloveho_portu, cislo_zdrojoveho_portu, cislo_cieloveho_portu, 4);
						if (strcmp(vnoreny_protokol, "ARP\n") == 0) alokuj_arp_strukturu(&struktura_arp_komunikacii, ramce, a);
						a++;
						}
						arp_dvojice(struktura_arp_komunikacii, ramce, ramce->smernik_na_data, vystupny_subor, subor_s_portmi_a_protokolmi);
					}
				}
		}

		if(pcap_subor != NULL) pcap_close(pcap_subor);
		pocet_ramcov = 0;
		printf("Zadajte cestu k suboru na analyzu alebo napiste koniec pre ukoncenie\n");
		scanf("%s", cesta_k_suboru_na_analyzu);
	}

	fclose(subor_s_portmi_a_protokolmi);
	fclose(vystupny_subor);

	return 0;
}