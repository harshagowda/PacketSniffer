#include <iostream>
#include <pcap.h>
#include <string>
#include <cstring>
#include <iostream>
#include <vector>
#include <memory>

using namespace std;

class PcapAddr {
	//struct pcap_addr {
	//	struct pcap_addr* next;
	//	struct sockaddr* addr;		/* address */
	//	struct sockaddr* netmask;	/* netmask for that address */
	//	struct sockaddr* broadaddr;	/* broadcast address for that address */
	//	struct sockaddr* dstaddr;	/* P2P destination address for that address */
	//};
public:
	struct sockaddr addr;		/* address */
	struct sockaddr netmask;	/* netmask for that address */
	struct sockaddr broadaddr;	/* broadcast address for that address */
	struct sockaddr dstaddr;	/* P2P destination address for that address */

};


class PcapIf {

	//	struct pcap_if {
	//	struct pcap_if *next;
	//	char *name;		/* name to hand to "pcap_open_live()" */
	//	char* description;	/* textual description of interface, or NULL */
	//	struct pcap_addr* addresses;
	//	bpf_u_int32 flags;	/* PCAP_IF_ interface flags */
	//	};

public:
	string name;
	string discription;
	vector<PcapAddr> addresses;
	bpf_u_int32 flags;
};


class LibPcap {
public:

	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_if_t* alldev_list_head;
	vector<PcapIf> nw_devices;

	LibPcap() {
		pcap_if_t* alldevsp = nullptr;
		int return_value = pcap_findalldevs(&alldevsp, error_buffer);


		if (return_value == PCAP_ERROR)
			cerr << "Failed: pcap_findalldevs" << endl;

		alldev_list_head = alldevsp;

		while (alldevsp)
		{
			PcapIf temp;
			copy_device_data(alldevsp, temp);
			nw_devices.emplace_back(temp);
			alldevsp = alldevsp->next;
		}

	}

	template <typename K>
	void copy_if_not_null(K* dest, K* src, unsigned long size)
	{
		if (src)
			memcpy(dest, src, size);
		else
			memset(dest, 0, size);
	}

	void copy_address(struct pcap_addr* addresses, PcapIf& PcapIftemp)
	{

		while (addresses)
		{
			PcapAddr PcapAddrtemp;
			copy_if_not_null<sockaddr>(&PcapAddrtemp.addr, addresses->addr, sizeof(struct sockaddr));
			copy_if_not_null<sockaddr>(&PcapAddrtemp.netmask, addresses->netmask, sizeof(struct sockaddr));
			copy_if_not_null<sockaddr>(&PcapAddrtemp.broadaddr, addresses->broadaddr, sizeof(struct sockaddr));
			copy_if_not_null<sockaddr>(&PcapAddrtemp.dstaddr, addresses->dstaddr, sizeof(struct sockaddr));
			PcapIftemp.addresses.emplace_back(PcapAddrtemp);
			addresses = addresses->next;
		}
	}

	void copy_device_data(pcap_if_t* pcap_device, PcapIf& PcapIftemp)
	{
		PcapIftemp.name = string(pcap_device->name);

		if (pcap_device->description != NULL)
			PcapIftemp.discription = string(pcap_device->description);
		PcapIftemp.flags = pcap_device->flags;
		copy_address(pcap_device->addresses, PcapIftemp);


	}

	void print_devices()
	{
		for (auto dev : nw_devices)
		{
			cout << dev.name << endl;
		}
	}

	~LibPcap() {
		pcap_freealldevs(alldev_list_head);
		cout << "libpcap destructor" << endl;
	}
};

#if 1
int main() {
	LibPcap libpcap;
	libpcap.print_devices();

	return 0;
}

#else


int main() {
	std::cout << PCAP_ERRBUF_SIZE << std::endl;
	return 0;
}

#endif