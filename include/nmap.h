
#ifndef NMAP_H
#define NMAP_H

#include <string>
using std::string;
/* Keep assert() defined for security reasons */
#include <assert.h>

/*******  DEFINES  ************/

const string NMAP_VERSION = "7.70SVN";
const string NMAP_NUM_VERSION = "7.0.70.100";

const string NMAP_UPDATE_CHANNEL = "7.70";

const string NMAP_XMLOUTPUTVERSION = "1.04";

/* User configurable #defines: */
const int MAX_PROBE_PORTS = 10; /* How many TCP probe ports are allowed ? */
/* Default number of ports in parallel.  Doesn't always involve actual
   sockets.  Can also adjust with the -M command line option.  */
const int MAX_SOCKETS = 36;

const int MAX_TIMEOUTS = MAX_SOCKETS;  /* How many timed out connection attempts
                                      in a row before we decide the host is
                                      dead? */
const int DEFAULT_TCP_PROBE_PORT = 80; /* The ports TCP ping probes go to if
                                     unspecified by user -- uber hackers
                                     change this to 113 */
const string DEFAULT_TCP_PROBE_PORT_SPEC = std::to_string(DEFAULT_TCP_PROBE_PORT);
const int DEFAULT_UDP_PROBE_PORT = 40125; /* The port UDP ping probes go to
                                          if unspecified by user */
const string DEFAULT_UDP_PROBE_PORT_SPEC = std::to_string(DEFAULT_UDP_PROBE_PORT);
const int DEFAULT_SCTP_PROBE_PORT = 80; /* The port SCTP probes go to
                                      if unspecified by
                                      user */
const string DEFAULT_SCTP_PROBE_PORT_SPEC = std::to_string(DEFAULT_SCTP_PROBE_PORT);
const string DEFAULT_PROTO_PROBE_PORT_SPEC = "1,2,4"; /* The IPProto ping probes to use
                                                 if unspecified by user */

const int MAX_DECOYS = 128; /* How many decoys are allowed? */

/* TCP Options for TCP SYN probes: MSS 1460 TODOs */
#define TCP_SYN_PROBE_OPTIONS "\x02\x04\x05\xb4";
#define TCP_SYN_PROBE_OPTIONS_LEN (sizeof(TCP_SYN_PROBE_OPTIONS) - 1);

/* Default maximum send delay between probes to the same host */
const int MAX_TCP_SCAN_DELAY = 1000;
const int MAX_UDP_SCAN_DELAY = 1000;

const int MAX_SCTP_SCAN_DELAY = 1000;

/* Maximum number of extra hostnames, OSs, and devices, we
   consider when outputting the extra service info fields */
const int MAX_SERVICE_INFO_FIELDS = 5;

/* We wait at least 100 ms for a response by default - while that
   seems aggressive, waiting too long can cause us to fail to detect
   drops until many probes later on extremely low-latency
   networks (such as localhost scans).  */

const int MIN_RTT_TIMEOUT = 100;

const int MAX_RTT_TIMEOUT = 10000; /* Never allow more than 10 secs for packet round
                                 trip */

const int INITIAL_RTT_TIMEOUT = 1000;    /* Allow 1 second initially for packet responses */
const int INITIAL_ARP_RTT_TIMEOUT = 200; /* The initial timeout for ARP is lower */

const int MAX_RETRANSMISSIONS = 10; /* 11 probes to port at maximum */

/* Number of hosts we pre-ping and then scan.  We do a lot more if
   randomize_hosts is set.  Every one you add to this leads to ~1K of
   extra always-resident memory in nmap */
const int PING_GROUP_SZ = 4096;

/* DO NOT change stuff after this point */
#define UC(b) (((int)b) & 0xff)
// TODO #define SA    struct sockaddr  /*Ubertechnique from R. Stevens */

const int HOST_UNKNOWN = 0;
const int HOST_UP = 1;
const int HOST_DOWN = 2;
const int PINGTYPE_UNKNOWN = 0;
const int PINGTYPE_NONE = 1;
const int PINGTYPE_ICMP_PING = 2;
const int PINGTYPE_ICMP_MASK = 4;
const int PINGTYPE_ICMP_TS = 8;
const int PINGTYPE_TCP = 16;
const int PINGTYPE_TCP_USE_ACK = 32;
const int PINGTYPE_TCP_USE_SYN = 64;

/* # define PINGTYPE_RAWTCP 128 used to be here, but was never used. */
const int PINGTYPE_CONNECTTCP = 256;
const int PINGTYPE_UDP = 512;

/* #define PINGTYPE_ARP 1024 // Not used; see o.implicitARPPing */
const int PINGTYPE_PROTO = 2048;
const int PINGTYPE_SCTP_INIT = 4096;

/* Empirically determined optimum combinations of different numbers of probes:
     -PE
     -PE -PA80
     -PE -PA80 -PS443
     -PE -PA80 -PS443 -PP
     -PE -PA80 -PS443 -PP -PU40125
   We use the four-probe combination. */
const int DEFAULT_IPV4_PING_TYPES = (PINGTYPE_ICMP_PING | PINGTYPE_TCP | PINGTYPE_TCP_USE_ACK | PINGTYPE_TCP_USE_SYN | PINGTYPE_ICMP_TS);
const int DEFAULT_IPV6_PING_TYPES = (PINGTYPE_ICMP_PING | PINGTYPE_TCP | PINGTYPE_TCP_USE_ACK | PINGTYPE_TCP_USE_SYN);
const string DEFAULT_PING_ACK_PORT_SPEC = "80";
 const string DEFAULT_PING_SYN_PORT_SPEC = "443";
/* For nonroot. */
const string DEFAULT_PING_CONNECT_PORT_SPEC = "80,443";

/* The max length of each line of the subject fingerprint when
   wrapped. */
const int FP_RESULT_WRAP_LINE_LEN = 74;

const int MAXHOSTNAMELEN = 64;

/* Length of longest DNS name */
const int FQDN_LEN = 254;

/* Max payload: Worst case is IPv4 with 40bytes of options and TCP with 20
 * bytes of options. */
const int MAX_PAYLOAD_ALLOWED = 65535 - 60 - 40;

/* Renamed main so that interactive mode could preprocess when necessary */
int nmap_main(int argc, char *argv[]);

int nmap_fetchfile(char *filename_returned, int bufferlen, const char *file);
int gather_logfile_resumption_state(char *fname, int *myargc, char ***myargv);

#endif /* NMAP_H */
