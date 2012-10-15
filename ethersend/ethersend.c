/*
 * For your first assignment, you will write a C program that constructs Ethernet packets to send a file.
 *
 * Your program should accept two arguments on the command line---ethernet source and destination addresses in the standard format consisting of 12 hex digits separated by six colons, e.g. 01:23:45:67:89:ab
 *
 * The program should read a file from standard input, package it up into Ethernet packets in the format described in the book, and write the packets on standard output. Each packet should have the source and destination address, a type field indicating type 0xabcd, and a four-byte block of zeros where the FCS should be. (Extra credit for putting a correct Ethernet CRC in there.)
 *
 * The payload of each data packet should be the next portion of the file: the payload should be 1500 bytes.
 *
 * The last data packet should be followed by a packet of maximum length containing the 32-bit checksum of the file contents, in network byte order (most significant byte first, i.e. "big-endian"). The checksum is computed by simply adding each byte of the file into a 32-bit register, discarding overflow.
 *
 * You must submit the following:
 *
 * Your C source code, together with any other files needed to try it out.
 *
 * A README.homework file containing a writeup in plain text of not more than 1000 words describing what you did, how it worked, and anything else you think we should know.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define PACKET_TYPE 0xABCD // 2 byte
#define MAX_PAYLOAD 1500
#define MIN_PAYLOAD 46 // 64 for the frame
#define FCS 0x00000000 // 4 byte, big-endian

int assic = 0;

void copyright() {
  printf("ethersend version 1.00.0\n");
  printf("Copyright 2012 - 2012 Derek Qian - http://web.cecs.pdx.edu/~dejun\n");
}

void usage() {
  printf("Usage: ethersend src dest\n");
  printf("    or ethersend src dest -assic\n");
  printf("  src and dest should be in the format of xx:xx:xx:xx:xx:xx\n");
}

/*
 * convert address string to address array
 * if address_array is null, then the address_string format is checked.
 */
int address_string_to_array(char* address_string, unsigned char* address_array, int address_array_size) {
  int i = 0;

  if(address_string == NULL) {
    printf("address_string_to_array: address_string is NULL\n");
    return -1;
  }
  if(strlen(address_string) != 17) {
    printf("address_string_to_array: address_string length error\n");
    return -1;
  }
  for(i=0; i<17; i++) {
    switch(i) {
    case 0:
    case 1:
    case 3:
    case 4:
    case 6:
    case 7:
    case 9:
    case 10:
    case 12:
    case 13:
    case 15:
    case 16:
      if(!((address_string[i]>='0') && (address_string[i]<='9') || (address_string[i]>='a') && (address_string[i]<='f') || (address_string[i]>='A') && (address_string[i]<='F'))) {
	printf("address_string_to_array: address_string not expected hex number\n");
	return -1;
      }
      break;
    case 2:
    case 5:
    case 8:
    case 11:
    case 14:
      if(address_string[i] != ':') {
	printf("address_string_to_array: address_string not expected : mark\n");
	return -1;
      }
      break;
    default:
      break;
    }
  }
  if(address_array == NULL) {
    return 0;
  }
  if(address_array_size != 6) {
    printf("address_string_to_array: address_array_size error\n");
    return -1;
  }
  for(i=0; i<17; i=i+3) {
    char temp = address_string[i];
    unsigned char hex1 = (temp>='0' && temp<='9') ? (temp-'0') : (tolower(temp)-'a'+10);
    temp = address_string[i+1];
    unsigned char hex2 = (temp>='0' && temp<='9') ? (temp-'0') : (tolower(temp)-'a'+10);
    address_array[i/3] = hex1*16 + hex2;
  }
  return 0;
}

void dump_packet(unsigned char* packet, int packetsize) {
  static int pos = 0;
  static int line = 0;
  int i;
  //printf("dump packet:\n");
  for(i=0; i<packetsize; i++) {
    if(pos%16 == 0) {
      printf("%04d ", line);
      line++;
    }
    printf("%02x ", packet[i]);
    if((pos+1)%16 == 0) {
      printf("\n");
    }
    pos++;
  }
  /*if(packetsize%16 != 0) {
    printf("\n");
    }*/
}

/*
 * calculating crc
 * modified from: http://bochs.sourceforge.net/cgi-bin/lxr/source/crc.cc
 * least significant bit first
 */
static unsigned int crc32_table[256];
#define CRC32_POLY 0x04c11db7
void init_crc32(void) {
  int i, j;
  unsigned int c;

  for(i=0; i<256; i++) {
    for(c=i<<24, j=8; j>0; j--)
      c = c & 0x80000000 ? (c << 1) ^ CRC32_POLY : (c << 1);
    crc32_table[i] = c;
  }
}
unsigned int cal_crc32(const unsigned char* buf, int len) {
  const unsigned char *p;
  unsigned int crc;
 
  if (!crc32_table[1])    /* if not already done, */
    init_crc32();   /* build table */
 
  crc = 0xffffffff;       /* preload shift register, per CRC-32 spec */
  for(p = buf; len > 0; ++p, --len)
    crc = (crc << 8) ^ crc32_table[(crc >> 24) ^ *p];
  return ~crc;            /* transmit complement, per CRC-32 spec */
}

void packet_gen(unsigned char src[6], unsigned char dest[6], unsigned short type, unsigned char* data, int datasize) {
  unsigned char packet[1518] = {0};
  int packetsize = 0;
  memcpy(packet, dest, 6*sizeof(unsigned char));
  memcpy(packet+6, src, 6*sizeof(unsigned char));
  packet[12] = type >> 8;
  packet[13] = type;
  memcpy(packet+14, data, datasize*sizeof(unsigned char));
  if(datasize < MAX_PAYLOAD) {
    unsigned int crc32 = cal_crc32(packet, 14+MAX_PAYLOAD);
    packet[14+MAX_PAYLOAD] = crc32 >> 24;
    packet[14+MAX_PAYLOAD+1] = crc32 >> 16;
    packet[14+MAX_PAYLOAD+2] = crc32 >> 8;
    packet[14+MAX_PAYLOAD+3] = crc32;
    packetsize = 14+MAX_PAYLOAD+4;
  } else {
    unsigned int crc32 = cal_crc32(packet, 14+datasize);
    packet[14+datasize] = crc32 >> 24;
    packet[14+datasize+1] = crc32 >> 16;
    packet[14+datasize+2] = crc32 >> 8;
    packet[14+datasize+3] = crc32;
    packetsize = 14+datasize+4;
  }
  if(assic) {
    dump_packet(packet, packetsize);
  } else {
    fwrite(packet, sizeof(unsigned char), packetsize, stdout);
  }
}

int main(int argc, char** argv) {
  int i;

  switch(argc) {
  case 3:
    break;
  case 4:
    assic = 1;
    break;
  default:
    copyright();
    usage();
  }

  unsigned char src[6];
  if(address_string_to_array(argv[1], src, 6) != 0) {
    printf("main: src address format error\n\n");
    usage();
    return -1;
  }
  //printf("epbuilder: src address %02x:%02x:%02x:%02x:%02x:%02x\n", src[0], src[1], src[2], src[3], src[4], src[5]);
  unsigned char dest[6];
  if(address_string_to_array(argv[2], dest, 6) != 0) {
    printf("main: dest address format error\n\n");
    usage();
    return -1;
  }
  //printf("epbuilder: dest address %02x:%02x:%02x:%02x:%02x:%02x\n", dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]);

  fseek(stdin, 0, SEEK_END);
  long filesize = ftell(stdin);
  fseek(stdin, 0, SEEK_SET);
  unsigned char* buf = malloc(filesize*sizeof(unsigned char));
  if(buf == NULL) {
    printf("main: create buffer failed\n");
    goto quit_point;
  }
  if(fread(buf, sizeof(unsigned char), filesize, stdin) != filesize) {
    printf("main: read file content into buffer failed\n");
    goto quit_point;
  }

  long sizeleft = filesize;
  unsigned char* curptr = buf;
  while(sizeleft > 0) {
    int packetsize = sizeleft > MAX_PAYLOAD ? MAX_PAYLOAD : sizeleft;
    //printf("Packet %d:\n", (int)(curptr-buf)/MAX_PAYLOAD);
    packet_gen(src, dest, PACKET_TYPE, curptr, packetsize);
    sizeleft = sizeleft - packetsize;
    curptr = curptr + packetsize;
  }

  // checksum for the file content
  unsigned int filechecksum = 0;
  for(i=0; i<filesize; i++) {
    filechecksum += buf[i];
  }
  //printf("Packet of checksum:\n");
  packet_gen(src, dest, PACKET_TYPE, (unsigned char*)&filechecksum, sizeof(filechecksum));

  if(assic) {
    printf("\n");
  }

quit_point:
  if(buf != NULL) {
    free(buf);
  }

  return 0;
}
