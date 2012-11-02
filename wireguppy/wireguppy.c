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


void print_ether() {
    int i;
    printf("%02x", getchar());
    for (i = 1; i < 6; i++)
        printf(":%02x", getchar());
}

int get16(void) {
    int b1 = getchar();
    int b2 = getchar();
    return ((b1 << 8) & 0xff00) | (b2 & 0xff);
}

int get32(void) {
    int b1 = getchar();
    int b2 = getchar();
    int b3 = getchar();
    int b4 = getchar();
    return
        ((b1 << 24) & 0xff000000) |
        ((b2 << 16) & 0xff0000) |
        ((b3 << 8) & 0xff00) |
        (b4 & 0xff);
}

void usage() {
  printf("Usage: ./wireguppy < input.pcap\n");
  printf("    or ./wireguppy -r < input.pcap for raw file\n");
}

int main(int argc, char **argv) {
  int raw_mode = 0;
  struct GlobalHeader ghead;
  struct PacketHeader phead;

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
  if (!raw_mode) {
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
    int length_type;
    int ch, paylen;

    printf("\n");

    // packet header
    if (!raw_mode) {
      // XXX Should use length information in decoding below.
      fread(&phead, sizeof(unsigned char), sizeof(struct PacketHeader), stdin);
      paylen = phead.packetsize;
      printf("paylen: %d (%d)\n", phead.packetsize, phead.payloadsize);
    }

    // data captured from wire
    printf("src: ");
    print_ether();
    printf("\n");
    printf("dst: ");
    print_ether();
    printf("\n");
    length_type = get16();
    if (length_type <= 1500) {
      // old style packet
      printf("Old style packet, length = %d\n", length_type);
      assert(0);
      for (i = 0; i < length_type; i++) {
        getchar();
      }
    } else if (length_type == 0x0800) {
      // ASSIGNMENT: MODIFY THIS TO PRINT INFORMATION ABOUT ENCAPSULATED PAYLOAD.
      (void) get16();
      length_type = get16();
      printf("IP: length %d\n", length_type);
      for (i = 0; i < length_type - 4; i++)
        (void) getchar();
    } else if(length_type == 0x0806) {
      printf("ARP packet\n");
      assert(0);
    } else if(length_type == 0x86DD) {
      printf("IPv6 packet\n");
      assert(0);
    } else {
      printf("Unexpected Ethernet packet\n");
      assert(0);
    }
    assert(phead.packetsize >= length_type - 14);
    if (!raw_mode) {
      paylen -= 14; // ethernet header
      paylen -= length_type; // IP packet
      for (i = 0; i < paylen; i++)
	printf("pad%d: %02x\n", i, getchar() & 0xff);
    }

    // test end of file
    ch = getchar();
    if (ch == EOF) {
      break;
    }
    ungetc(ch, stdin);
  }
  return 0;
}
