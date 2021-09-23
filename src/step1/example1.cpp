#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef WIN32
#include <WinSock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

int main(int argc, char* argv[])
{
	char* dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* alldevs;
	pcap_if_t* d;

	const auto ret = pcap_findalldevs(&alldevs, errbuf);
	if (ret != 0) {
		printf("%s\n", errbuf);
	}

	/* Print the list */
	for (d = alldevs; d != NULL; d = d->next)
	{
		if (d->description) {
			printf("desc: %s\n", d->description);
		}
		if (d->name) {
			printf("name: %s\n", d->name);
		}

		struct pcap_addr* cur_addr = NULL;
		if (d->addresses) {
			cur_addr = d->addresses;
			while (cur_addr != NULL)
			{
				const auto z = ((struct sockaddr_in*)cur_addr->addr)->sin_addr;
				printf("address %s\n", inet_ntoa(z));
				cur_addr = cur_addr->next;
			}
		}

		puts("");
	}

	pcap_freealldevs(alldevs);
	return 0;
}