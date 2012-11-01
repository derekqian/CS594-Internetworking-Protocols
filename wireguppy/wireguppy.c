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

struct Packet {
  unsigned int timestamp; // Unix epoch, second part
  unsigned int microsec; // microsecond part
  unsigned int packetsize; // size of the packet in the file
  unsigned int payloadsize; // size of the actual payload captured from the wire
  unsigned char data[0];
};

struct Ethernet {
  unsigned char dest[6];
  unsigned char src[6];
  unsigned short type;
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

int flip32(int x) {
    return
        ((x >> 24) & 0xff) |
        ((x >> 8) & 0xff00) |
        ((x << 8) & 0xff0000) |
        ((x << 24) & 0xff000000);
}

int decode_length_type() {
    int length_type = get16();
    if (length_type == 0x8100) {
        printf("VLAN: %04x\n", get16());
        length_type = get16();
    }
    printf("length/type: %04x\n", length_type);
    return length_type;
}

/* ASSIGNMENT: MODIFY THIS TO PRINT INFORMATION ABOUT
   ENCAPSULATED PAYLOAD. */
int show_ip() {
    int i, length;
    (void) get16();
    length = get16();
    printf("IP: length %d\n", length);
    for (i = 0; i < length - 4; i++)
        (void) getchar();
    return length;
}

void show_payload(int lt) {
    int i;
    for (i = 0; i < lt; i++)
        getchar();
}

int raw_mode = 0;

int main(int argc, char **argv) {
    int i;
    if (argc == 2) {
        assert(!strcmp(argv[1], "-r"));
        raw_mode = 1;
    } else {
        assert(argc == 1);
    }
    if (!raw_mode) {
        /* XXX Should check link type and
           record snapshot length. */
        for (i = 0; i < 6; i++)
            printf("h%d: %08x\n", i, get32());
        printf("\n");
    }
    while (1) {
        int lt, ch, paylen;
        if (!raw_mode) {
            /* XXX Should use length information
               in decoding below. */
            (void) get32();
            (void) get32();
            paylen = flip32(get32());
            printf("paylen: %d (%d)\n", paylen, flip32(get32()));
        }
        printf("src: ");
        print_ether();
        printf("\n");
        printf("dst: ");
        print_ether();
        printf("\n");
        lt = decode_length_type();
        if (lt == 0x0800)
            lt = show_ip();
        else if (lt <= 1500)
            show_payload(lt);
        else
            assert(0);
        assert(paylen >= lt - 14);
        if (!raw_mode) {
            paylen -= 14; /* ethernet header */
            paylen -= lt; /* IP packet */
            for (i = 0; i < paylen; i++)
                printf("pad%d: %02x\n", i, getchar() & 0xff);
        }
        ch = getchar();
        if (ch == EOF)
            break;
        (void) ungetc(ch, stdin);
        printf("\n");
    }
    return 0;
}
