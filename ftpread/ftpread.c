/*
 * Copyright © 2012 Bart Massey
 * [This program is licensed under the "MIT License"]
 * Please see the file COPYING in the source
 * distribution of this software for license terms.
 */


/* TFTP client read program. */

/*
 * In this assignment, you will write ftpread, an FTP reader client in C in the style of the tftpread program written in class.
 *
 * FTP is described in RFC 959. You should start by reading and thoroughly understanding the relevant portions of this RFC.
 *
 * Your client will start by making a TCP "control" connection to the FTP daemon on a host specified on the command line. You will then establish a TCP "data" connection to retrieve a file at a path specified on the command line, writing the retrieved file to standard output as tftpread does.
 *
 * Your client must authenticate itself with username "anonymous" (spelled correctly) and your email address as the "password", as per the specifications for anonymous FTP.
 *
 * Your client must be able to retrieve a file in binary stream mode. There are two basic types of retrieve: "active" and "passive". In an active FTP retrieve, you listen for a data connection, then retrieve the file from that data connection when the server connects to you. In a passive FTP retrieve, you connect to a port specified by the server and retrieve the data from there.
 *
 * For the purposes of this assignment, you are successful when your ftpread program can retrieve the file hello.txt from the host svcs.cs.pdx.edu using FTP. CS 494 students may choose to do only an active retrieve. The tftpread of CS 594 students must be able to do either an active or passive retrieve, as specified on the command line.
 *
 * Hints
 *
 * This is a fairly challenging assignment. Here's some hints to make it easier.
 *
 * tftpread
 *
 * You may want to start with tftpread, available on my Github (https://github.com/BartMassey/). It contains a bunch of code that is similar to code you will need for ftpread. If you cannot use git, note that there is a "ZIP" button near the top left of the page that will create a ZIP archive to download.
 *
 * fdopen()
 *
 * You will be sending a lot of commands, and parsing a lot of responses. One good trick is to use fdopen() to turn the file descriptor of your socket into a FILE * suitable for use with standard IO functions such as printf() and scanf(). Note that you need to fdopen() the input and output of the socket separately, else you may get confusion with buffering.
 *
 *    FILE *s_in = fdopen(s, "r");
 *    FILE *s_out = fdopen(s, "w");
 *
 * expect / send
 *
 * Parsing response codes gets pretty tedious too, so you will want some code to handle that. I recommend my "expect / send" library, also available on my GitHub. This (documented) C library provides simple functions for sending commands and dealing with expected responses.
 *
 * You will probably want to just hardwire your client to not handle unexpected response codes gracefully: just exit. That's what my expect / send library does, and it's fine for this assignment. The easiest way to discover what response codes to expect is via experimentation.
 *
 * The PORT command
 *
 * Whether doing an active or passive transfer, you will need to use the PORT command to inform the server of the IP address and port number of your end of the socket. The best way to get this information is via the getsockname() call. Make sure you send the PORT bytes in network order.
 *
 * Passive transfers
 *
 * The order of operations for a passive transfer is pretty specific: you must send PORT, then PASV, then connect() the data socket, then RETR. Any other order is unlikely to work.
 * 
 * Debugging
 *
 * You will want to get a real FTP client and try retrieving the specified file that way. Use wireshark / tshark to watch the flow of commands and responses during the transaction; this is basically what you are trying to duplicate.
 *
 * Make sure you turn on the cexpect_verbose variable in my expect / send library if you are using that library; it is really useful to see what your program is doing.
 *
 * Misc Hints
 *
 * It is really easy to get host and network byte-order problems. The routines htonl(), ntohl(), htons() and ntohs() do conversions between host and network byte order for short (16-bit, like port numbers) and long (32-bit, like IP addresses) integers.
 *
 * The routine inet_ntoa() will convert a 32-bit IPv4 address into a string for printing purposes.
 *
 * Submission
 *
 * You must submit the following:
 *
 * Your C source code, together with any other files needed to try it out.
 *
 * A README.homework file containing a writeup in plain text of not more than 1000 words describing what you did, how it worked, and anything else you think we should know.
 */

#include <assert.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#define VERBOSE 
#ifdef VERBOSE
#define dbgmsg(msg) printf msg
#else
#define dbgmsg(msg) 
#endif

static unsigned char msgbuf[516];

static int format_rrq(char *filename) {
    char *modestr = "octet";
    msgbuf[0] = 0;
    msgbuf[1] = 1;
    strcpy((char *)msgbuf + 2, filename);
    strcpy((char *)msgbuf + 2 + strlen(filename) + 1, modestr);
    return 2 + strlen(filename) + 1 + strlen(modestr) + 1;
}

static int process_response(int msglen, int blocknum) {
    /* XXX should check msglen in case of corrupt packet */
    unsigned short opcode = (msgbuf[0] << 8) | msgbuf[1];
    switch (opcode) {
    case 5 /* error */:
        fprintf(stderr, "error: %s\n", msgbuf + 4);
        exit(1);
    case 3 /* data */: {
        int actualblock = (msgbuf[2] << 8) | msgbuf[3];
        if (actualblock != blocknum) {
            fprintf(stderr, "received unexpected block %d\n", actualblock);
            return -1;
        }
        int r = fwrite(msgbuf + 4, 1, msglen - 4, stdout);
        assert(r == msglen - 4);
        return msglen - 4; }
    }
    fprintf(stderr, "unknown opcode 0x%04x received, giving up\n", opcode);
    exit(1);
}

void format_ack(int blocknum) {
    msgbuf[0] = 0;
    msgbuf[1] = 4;
    msgbuf[2] = (blocknum >> 8) & 0xff;
    msgbuf[3] = blocknum & 0xff;
}

void usage() {
  printf("ftpread version 1.0\n");
  printf("Usage: ftpread [-passive/-active] hostname filename\n");
}

int main(int argc, char **argv) {
  char hostname[128];
  char filename[128];
  int passive = 1;

  if(argc<3 || argc>4) {
    usage();
    return 0;
  } else if(argc==3) {
    strcpy(hostname, argv[1]);
    strcpy(filename, argv[2]);
  } else {
    if(0 == strcmp(argv[1], "-passive")) {
      passive = 1;
    } else if(0 == strcmp(argv[1], "-active")) {
      passive = 0;
    } else {
      usage();
      return 0;
    }
    strcpy(hostname, argv[2]);
    strcpy(filename, argv[3]);
  }

  dbgmsg(("parameter: passive? %d\n", passive));
  dbgmsg(("hostname: %s\n", hostname));
  dbgmsg(("filename: %s\n", filename));

  struct in_addr inp;
  struct hostent *h = NULL;
#if 1
  if(0 != inet_aton(hostname, &inp)) {
#else
  if(0 != inet_pton(AF_INET, hostname, &inp)) {
#endif
    h = gethostbyaddr(&inp, sizeof(inp), AF_INET);
  } else {
    h = gethostbyname(hostname);
  }
  if(!h) {
    herror("bad destination");
    exit(1);
  }
  assert(h->h_addrtype == AF_INET);
  dbgmsg(("ip address: %d.%d.%d.%d\n", (unsigned char)h->h_addr[0], (unsigned char)h->h_addr[1], (unsigned char)h->h_addr[2], (unsigned char)h->h_addr[3]));

  int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  assert(s != -1);

  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = htons(21); // FTP port number
  /* XXX Should try all the addresses in the list. */
  sin.sin_addr.s_addr = *(uint32_t *)h->h_addr;

    int size = format_rrq(argv[2]);
    int r = sendto(s, msgbuf, size, 0,
                   (const struct sockaddr *)&sin, (socklen_t)sizeof(sin));
    assert(r == size);

    struct sockaddr_in ssin;
    socklen_t ssaddrlen = sizeof(ssin);
    r = recvfrom(s, (void *)msgbuf, sizeof(msgbuf), 0,
                 (struct sockaddr *)&ssin, &ssaddrlen);
    assert(r >= 0);

    int blocknum = 1;
    while (1) {
        int transferred = process_response(r, blocknum);
        if (transferred == -1)
            continue;
        format_ack(blocknum);
        r = sendto(s, msgbuf, size, 0,
                   (const struct sockaddr *)&ssin, (socklen_t)sizeof(ssin));
        if (transferred < 512) {
#ifdef DEBUG
            fprintf(stderr, "processing last %d bytes\n", transferred);
#endif
            break;
        }
        ssaddrlen = sizeof(ssin);
        r = recvfrom(s, (void *)msgbuf, sizeof(msgbuf), 0,
                     (struct sockaddr *)&ssin, &ssaddrlen);
        assert(r >= 0);
        blocknum++;
    }

    return 0;
}
