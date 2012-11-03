/*
 * Copyright © 2012 Bart Massey
 * [This program is licensed under the "MIT License"]
 * Please see the file COPYING in the source
 * distribution of this software for license terms.
 */

/*
 * One really useful tool for measuring networks is a packet trace analyzer. A packet trace analyzer is a tool that takes packets read from the network and decodes them to reveal what is inside in a human-readable format. The most popular trace analyzer in general use these days is probably Wireshark, a GUI tool, and its command-line cousin tshark.
 *
 * I have written C code for a tiny, incomplete, broken cousin of tshark I call wireguppy. Wireguppy reads a packet trace file in PCAP format (taken from the network using a packet capture program such as tcpdump), and displays some very basic information about each packet in the trace---or maybe just crashes.
 *
 * Your assignment is to improve Wireguppy. At least, you must make wireguppy decode interesting information from the headers of TCP or UDP payloads of ethernet packets in a trace provided with the wireguppy distribution. At best, you will make Wireguppy handle weird packet types and try it on traces you capture yourself.
 *
 * You can get a copy of the Wireguppy source as a ZIP archive from http://svcs.cs.pdx.edu/tarballs/wireguppy.zip (or get a tarball from wireguppy.tar.gz. You can also clone git://svcs.cs.pdx.edu/git/wireguppy.git if you are familiar with Git.
 *
 * You must submit the following:
 *   . Your modified wireguppy C source code, together with any other files needed to try it out.
 *   . A README.homework file containing a writeup in plain text of not more than 1000 words describing what you did, how it worked, and anything else you think we should know.
*/

/*
 * pcap file format
 * http://kroosec.blogspot.com/2012/10/a-look-at-pcap-file-format.html
*/

/* Decode captured packet stream */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC_NUMBER 0xA1B2C3D4

struct GlobalHeader {
  unsigned int magic; // 0xA1B2C3D4
  unsigned short majorver;
  unsigned short minorver;
  unsigned int timezoneoffset;
  unsigned int timestamp;
  unsigned int snapshotlenght; // the maximum lenght for captured packets, usually 0xffff for tcpdump and wireshark.
  unsigned int linklayertype; // 0x01 means the link layer protocol is Ethernet
};

struct PacketHeader {
  unsigned int timestamp; // Unix epoch, second part
  unsigned int microsec; // microsecond part
  unsigned int packetsize; // size of the packet in the file
  unsigned int payloadsize; // size of the actual payload captured from the wire
};

struct EthernetHeader {
  unsigned char dest[6];
  unsigned char src[6];
  unsigned short length_type;
};

struct IPv4Header {
  unsigned char byte0;
  unsigned char byte1;
  unsigned short datalen; // size including the header
  unsigned short id;
  unsigned short word0;
  unsigned char TTL;
  unsigned char protocol;
  unsigned short headchecksum;
  unsigned char src[4];
  unsigned char dest[4];
};

struct UDPHeader {
  unsigned short src;
  unsigned short dest;
  unsigned short size;
  unsigned short checksum;
};

struct TCPHeader {
  unsigned short src;
  unsigned short dest;
  unsigned int seqnum;
  unsigned int acknum;
  unsigned char byte0;
  unsigned char byte1;
  unsigned short winsize;
  unsigned short checksum;
  unsigned short urgpoint;
};


int get8(void) {
  int b1 = getchar();
  if(b1 == EOF) exit(0);
  return b1;
}

int get16(void) {
    int b1 = getchar();
  if(b1 == EOF) exit(0);
    int b2 = getchar();
  if(b2 == EOF) exit(0);
    return ((b1 << 8) & 0xff00) | (b2 & 0xff);
}

int get32(void) {
    int b1 = getchar();
  if(b1 == EOF) exit(0);
    int b2 = getchar();
  if(b2 == EOF) exit(0);
    int b3 = getchar();
  if(b3 == EOF) exit(0);
    int b4 = getchar();
  if(b4 == EOF) exit(0);
    return
        ((b1 << 24) & 0xff000000) |
        ((b2 << 16) & 0xff0000) |
        ((b3 << 8) & 0xff00) |
        (b4 & 0xff);
}

void dump(int size, int screen) {
  int i;
  if(screen != 0) {
    for(i=0; i<size; i++) {
      if(i%16 == 0) {
	printf("%02x", get8());
      } else if(i%16 == 15) {
	printf(", %02x\n", get8());
      } else {
	printf(", %02x", get8());
      }
    }
    if(i%16 != 0) {
      printf("\n");
    }
  } else {
    for(i=0; i<size; i++) {
      get8();
    }
  }
}

void get_ether(struct EthernetHeader* ehead) {
  int i;
  for(i=0; i<6; i++) {
    ehead->dest[i] = get8();
  }
  for(i=0; i<6; i++) {
    ehead->src[i] = get8();
  }
  ehead->length_type = get16();
}

void print_ether(struct EthernetHeader* ehead) {
    int i;
    printf("<<<Ethernet\n");
    printf("    %02x", ehead->src[0]);
    for (i = 1; i < 6; i++)
        printf(":%02x", ehead->src[i]);
    printf(" -> ");
    printf("%02x", ehead->dest[0]);
    for (i = 1; i < 6; i++)
        printf(":%02x", ehead->dest[i]);
    printf("\n");
}

void get_ipv4(struct IPv4Header* ip4head) {
  int i;
  ip4head->byte0 = get8();
  ip4head->byte1 = get8();
  ip4head->datalen = get16();
  ip4head->id = get16();
  ip4head->word0 = get16();
  ip4head->TTL = get8();
  ip4head->protocol= get8(); // 4 for ipv4, 6 for TCP, 17 for UDP
  ip4head->headchecksum = get16();
  for(i=0; i<4; i++) {
    ip4head->src[i] = get8();
  }
  for(i=0; i<4; i++) {
    ip4head->dest[i] = get8();
  }
}

void print_ipv4(struct IPv4Header* ip4head) {
  int i;
  printf("<<<IP\n");
  printf("    %d", ip4head->src[0]);
  for(i=1; i<4; i++) {
    printf(".%d", ip4head->src[i]);
  }
  printf(" -> ");
  printf("%d", ip4head->dest[0]);
  for(i=1; i<4; i++) {
    printf(".%d", ip4head->dest[i]);
  }
  printf("\n");
  printf("    id: %d\n", ip4head->id);
  printf("    length: %d\n", ip4head->datalen);
  printf("    TTL: %d\n", ip4head->TTL);
}

void get_udp(struct UDPHeader* udphead) {
  udphead->src = get16();
  udphead->dest = get16();
  udphead->size = get16();
  udphead->checksum = get16();
}

void print_udp(struct UDPHeader* udphead) {
  printf("<<<UDP\n");
  printf("    %d -> %d\n", udphead->src, udphead->dest);
  printf("    size: %d\n", udphead->size);
}

void get_tcp(struct TCPHeader* tcphead) {
  tcphead->src = get16();
  tcphead->dest = get16();
  tcphead->seqnum = get32();
  tcphead->acknum = get32();
  tcphead->byte0 = get8();
  tcphead->byte1 = get8();
  tcphead->winsize = get16();
  tcphead->checksum = get16();
  tcphead->urgpoint = get16();
}

void print_tcp(struct TCPHeader* tcphead) {
  printf("<<<TCP %s %s\n", tcphead->byte1&0x10?"ACK":"NACK", tcphead->byte1&0x02?"SYN":"NSYN");
  printf("    %d -> %d\n", tcphead->src, tcphead->dest);
  printf("    seq num: 0x%08x\n", tcphead->seqnum);
  printf("    ack num: 0x%08x\n", tcphead->acknum);
}

void usage() {
  printf("Usage: ./wireguppy < input.pcap\n");
  printf("    or ./wireguppy -r < input.pcap for raw file\n");
}

int main(int argc, char **argv) {
  int raw_mode = 0;
  struct GlobalHeader ghead;

  // parameter check
  if(argc == 1) {
    raw_mode = 0;
  } else if(argc == 2) {
    if(0 != strcmp(argv[1], "-r")) {
      usage();
      return 0;
    }
    raw_mode = 1;
  } else {
    usage();
    return 0;
  }

  // read global header
  if(!raw_mode) {
    // XXX Should check link type and record snapshot length.
    fread(&ghead, sizeof(unsigned char), sizeof(struct GlobalHeader), stdin);
    if(ghead.magic != MAGIC_NUMBER) {
      printf("invalid file format\n");
      return 0;
    }
    printf("PCAP format v%d.%d, ", ghead.majorver, ghead.minorver);
    if(ghead.linklayertype != 1) {
      printf("unsupported link layer type\n");
      return 0;
    }
    printf("link layer type: Ethernet.\n");
  }

  // read each packet
  while (1) {
    int i;
    struct PacketHeader phead;
    struct EthernetHeader ehead;

    printf("\n");

    // packet header
    if (!raw_mode) {
      // XXX Should use length information in decoding below.
      if(sizeof(struct PacketHeader) != fread(&phead, sizeof(unsigned char), sizeof(struct PacketHeader), stdin)) break;
      printf("<<<PCAP packet\n");
      printf("    packet size: %d\n", phead.packetsize);
      printf("    payload size: %d\n", phead.payloadsize);
    }

    // data captured from wire
    get_ether(&ehead);
    print_ether(&ehead);

    if (ehead.length_type <= 1500) {
      // old style packet
      printf("Old style packet, length = %d\n", ehead.length_type);
      printf("We don't support this packet now\n");
      if (!raw_mode) {
	dump(phead.packetsize-sizeof(ehead), 1);
      }
    } else if (ehead.length_type == 0x0800) {
      // ASSIGNMENT: MODIFY THIS TO PRINT INFORMATION ABOUT ENCAPSULATED PAYLOAD.
      struct IPv4Header ipv4head;
      get_ipv4(&ipv4head);
      print_ipv4(&ipv4head);

      if(ipv4head.protocol == 4) {
	printf("IP packet\n");
	printf("Wedon't support this packet now\n");
	dump(ipv4head.datalen-sizeof(ipv4head), 1);
      } else if(ipv4head.protocol ==  6) {
	struct TCPHeader tcphead;
	get_tcp(&tcphead);
	print_tcp(&tcphead);

	// get payload in TCP packet
	dump(ipv4head.datalen-sizeof(ipv4head)-sizeof(tcphead), 0);
      } else if(ipv4head.protocol == 17) {
	struct UDPHeader udphead;
	get_udp(&udphead);
	assert(udphead.size == ipv4head.datalen-sizeof(ipv4head));
	print_udp(&udphead);

	// get payload in UDP packet
	dump(udphead.size-sizeof(udphead), 0);
      } else {
	printf("Unexpected IP packet\n");
	dump(ipv4head.datalen-sizeof(ipv4head), 1);
      }

      if(!raw_mode) {
	if(phead.packetsize > sizeof(ehead)+ipv4head.datalen) {
	  printf("pad:\n");
	  dump(phead.packetsize-sizeof(ehead)-ipv4head.datalen, 1);
	}
      }
    } else if(ehead.length_type == 0x0806) {
      printf("ARP packet\n");
      printf("We don't support this packet now\n");
      if (!raw_mode) {
	dump(phead.packetsize-sizeof(ehead), 1);
      }
    } else if(ehead.length_type == 0x86DD) {
      printf("IPv6 packet\n");
      printf("We don't support this packet now\n");
      if (!raw_mode) {
	dump(phead.packetsize-sizeof(ehead), 1);
      }
    } else {
      printf("Unexpected Ethernet packet\n");
      if (!raw_mode) {
	dump(phead.packetsize-sizeof(ehead), 1);
      }
    }
  }
  return 0;
}
