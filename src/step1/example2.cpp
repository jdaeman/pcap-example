#include <pcap.h>

#ifdef inline
#undef inline
#endif

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <chrono>
#include <thread>
#ifdef WIN32
#include <WinSock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

void packet_handler(u_char* param,
                    const struct pcap_pkthdr* header, 
                    const u_char* pkt_data) 
{
    printf("caplen : %d\n", header->caplen);
    printf("len : %d\n", header->len);
}

int main(int argc, char** argv) 
{
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int i = 0;
    int no;

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("pcap_findalldevs error\n");
        return 1;
    }

    for (d = alldevs; d != NULL; d = d->next) {
        printf("%d :  %s\n", ++i, (d->description) ? (d->description) : (d->name));
    }

    printf("number : ");
    scanf("%d", &no);

    for (d = alldevs, i = 0; d != NULL; d = d->next) {
        if (no == ++i) {
            break;
        }
    }

    if (d == NULL) {
        printf("there is no dev\n");
        pcap_freealldevs(alldevs);
    }
    else {
        adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
        if (adhandle == NULL) {
            printf("pcap_open_live error %s\n", d->name);
            pcap_freealldevs(alldevs);
            return -1;
        }

        std::thread th([&adhandle]() {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            pcap_breakloop(adhandle);
            printf("Execute: pcap_breakloop()");
        });

        printf("Start: packet capture\n");

        pcap_freealldevs(alldevs);
        pcap_loop(adhandle, 0, packet_handler, NULL);
        pcap_close(adhandle);

        th.join();
    }

    return 0;
}