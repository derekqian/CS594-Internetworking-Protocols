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

#include "expect.h"


//#define VERBOSE 
#ifdef VERBOSE
#define dbgmsg(msg) printf msg
#else
#define dbgmsg(msg) 
#endif

static char* username = "anonymous";
static char* password = "dejun@pdx.edu";

static void usage() {
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
  printf("ftpread v1.0\n");

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
  FILE *s_in = fdopen(s, "r");
  assert(s_in != NULL);
  FILE *s_out = fdopen(s, "w");
  assert(s_out != NULL);

  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = htons(21); // FTP port number (rfc page 59)
  /* XXX Should try all the addresses in the list. */
  sin.sin_addr.s_addr = *(uint32_t *)h->h_addr;

  if(0 != connect(s, (struct sockaddr *)&sin, sizeof(sin))) {
    herror("connect failed");
    exit(1);
  }

  cexpect(s_in, 220, "Service ready for new user."); // page 39, section 4.2
  csend(s_out, "USER %s", username); // page 25, section 4
  cexpect(s_in, 331, "User name okay, need password.");
  csend(s_out, "PASS %s", password);
  cexpect(s_in, 230, "User logged in, proceed.");
  csend(s_out, "TYPE I");
  cexpect(s_in, 200, "Command okay.");
  if(passive ==1) {
    printf("mode: passive\n\n");

    uint32_t h1, h2, h3, h4, p1, p2;
    csend(s_out, "PASV");
    cexpect(s_in, 227, "Entering Passive Mode (h1,h2,h3,h4,p1,p2).");
    sscanf(cexpect_response, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).", &h1, &h2, &h3, &h4, &p1, &p2);
    csend(s_out, "RETR hello.txt");

    int t_s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(t_s != -1);

    struct sockaddr_in t_sin;
    t_sin.sin_family = AF_INET;
    t_sin.sin_port = p1 + (p2<<8);
    t_sin.sin_addr.s_addr = h1 + (h2<<8) + (h3<<16) + (h4<<24);

    if(0 != connect(t_s, (struct sockaddr *)&t_sin, sizeof(t_sin))) {
      herror("connect to data port failed");
      exit(1);
    }

    char buf[512];
    int r;
    while((r=read(t_s, buf, 512)) > 0) {
      write(1, buf, r);
    }

    shutdown(t_s, SHUT_RDWR);
    close(t_s);
  } else {
    printf("mode: active\n\n");

    uint32_t h1, h2, h3, h4, p1, p2;

    int t_s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(t_s != -1);

    struct sockaddr_in t_sin;
    memset(&t_sin, 0, sizeof(t_sin));
    socklen_t size = sizeof(t_sin);
    if(0 != getsockname(s, (struct sockaddr *)&t_sin, &size)) {
      herror("getsockname failed");
      exit(1);
    }
    dbgmsg(("%s:%d\n", inet_ntoa(t_sin.sin_addr), ntohs(t_sin.sin_port)));

    t_sin.sin_family = AF_INET;
    t_sin.sin_port = htons(0);
    //t_sin.sin_addr.s_addr = htonl(INADDR_ANY);
    if(-1 == bind(t_s, (struct sockaddr *)&t_sin, sizeof(t_sin))) {
      herror("bind failed");
      exit(1);
    }

    size = sizeof(t_sin);
    if(0 != getsockname(t_s, (struct sockaddr *)&t_sin, &size)) {
      herror("getsockname failed");
      exit(1);
    }
    dbgmsg(("%s:%d\n", inet_ntoa(t_sin.sin_addr), ntohs(t_sin.sin_port)));

    if(-1 == listen(t_s, 4)) {
      herror("listen failed");
      exit(1);
    }

    h1 = t_sin.sin_addr.s_addr & 0xff;
    h2 = (t_sin.sin_addr.s_addr>>8) & 0xff;
    h3 = (t_sin.sin_addr.s_addr>>16) & 0xff;
    h4 = (t_sin.sin_addr.s_addr>>24) & 0xff;
    p1 = t_sin.sin_port & 0xff;
    p2 = (t_sin.sin_port>>8) & 0xff;
    csend(s_out, "PORT %u,%u,%u,%u,%u,%u", h1, h2, h3, h4, p1, p2);
    cexpect(s_in, 200, "Command okay.");
    csend(s_out, "RETR hello.txt");

    int c_s = accept(t_s, NULL, NULL);
    if(c_s < 0) {
      herror("accept failed");
      exit(1);
    }

    char buf[512];
    int r;
    while((r=read(c_s, buf, 512)) > 0) {
      write(1, buf, r);
    }

    shutdown(c_s, SHUT_RDWR);
    close(c_s);

    close(t_s);
  }

  fclose(s_out);
  fclose(s_in);
  shutdown(s, SHUT_RDWR);
  close(s);
  return 0;
}
