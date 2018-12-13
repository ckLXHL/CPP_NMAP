#ifndef NMAP_OPS_H
#define NMAP_OPS_H

struct FingerPrintDB;
struct FingerMatch;
#include <string>
#include <chrono>
#include <unordered_map>
#include <vector>
#include "scanLists.h"
#include "nmap.h"
#include "log.h"

using std::string;
using std::chrono::duration;
using std::chrono::seconds;
using std::chrono::time_point;
using std::unordered_map;
using std::vector;

class NmapOps
{
  public:
    void ReInit();
    int addressFamily;
    int pf();
    int SourceSockAddr(string sockaddr);
    string SourceSockAddr();
    std::chrono::system_clock::time_point startTime;
    seconds DurationSinceStart(const std::chrono::system_clock::time_point now = std::chrono::system_clock::now());
    bool TCPScan();
    // TODO bool UDPScan();
    //bool SCTPScan();

    bool RawScan();
    void ValidateOptions();
    bool packetTrace() { return (debugging >= 3)? true: pTrace; }

    int isr00t;
    bool have_pcap;
    unsigned debugging;
    bool resuming;
    int sendpref;

    // func TODO 

    // constant
    const int PACKET_SEND_NOPREF = 1;
    const int PACKET_SEND_ETH_WEAK = 2;
    const int PACKET_SEND_ETH_STRONG = 4;
    const int PACKET_SEND_ETH = 6;
    const int PACKET_SEND_IP_WEAK = 8;
    const int PACKET_SEND_IP_STRONG = 16;
    const int PACKET_SEND_IP = 24;

    unsigned int max_ips_to_scan; // Used for Random input (-iR) to specify how
                       // many IPs to try before stopping. 0 means unlimited.
  int extra_payload_length; /* These two are for --data-length op */
  char *extra_payload;
  unsigned long host_timeout;
  /* Delay between probes, in milliseconds */
  unsigned int scan_delay;
  bool open_only;

  int scanflags; /* if not -1, this value should dictate the TCP flags
                    for the core portscanning routine (eg to change a
                    FIN scan into a PSH scan.  Sort of a hack, but can
                    be very useful sometimes. */

  bool defeat_rst_ratelimit; /* Solaris 9 rate-limits RSTs so scanning is very
            slow against it. If we don't distinguish between closed and filtered ports,
            we can get the list of open ports very fast */

  bool defeat_icmp_ratelimit; /* If a host rate-limits ICMP responses, then scanning
            is very slow against it. This option prevents Nmap to adjust timing
            when it changes the port's state because of ICMP response, as the latter
            might be rate-limited. Doing so we can get scan results faster. */

  // TODOs struct in_addr resume_ip; /* The last IP in the log file if user
                               //requested --restore .  Otherwise
                               //restore_ip.s_addr == 0.  Also
                               //target_struct_get will eventually set it
                               //to 0. */

  // Version Detection Options
  bool override_excludeports;
  int version_intensity;

  //TODOs struct sockaddr_storage decoys[MAX_DECOYS];
  bool osscan_limit; /* Skip OS Scan if no open or no closed TCP ports */
  bool osscan_guess;   /* Be more aggressive in guessing OS type */
  int numdecoys;
  int decoyturn;
  bool osscan;
  bool servicescan;
  int pingtype;
  int listscan;
  int fragscan; /* 0 or MTU (without IPv4 header size) */
  int ackscan;
  int bouncescan;
  int connectscan;
  int finscan;
  int idlescan;
  char* idleProxy; /* The idle host used to "Proxy" an idle scan */
  int ipprotscan;
  int maimonscan;
  int nullscan;
  int synscan;
  int udpscan;
  int sctpinitscan;
  int sctpcookieechoscan;
  int windowscan;
  int xmasscan;
  bool noresolve;
  bool noportscan;
  bool append_output; /* Append to any output files rather than overwrite */
  FILE *logfd[LOG_NUM_FILES];
  FILE *nmap_stdout; /* Nmap standard output */
  int ttl; // Time to live
  bool badsum;
  char *datadir;
  /* A map from abstract data file names like "nmap-services" and "nmap-os-db"
     to paths which have been requested by the user. nmap_fetchfile will return
     the file names defined in this map instead of searching for a matching
     file. */
  unordered_map<string, string> requested_data_files;
  /* A map from data file names to the paths at which they were actually found.
     Only files that were actually read should be in this map. */
  unordered_map<string, string> loaded_data_files;
  bool mass_dns;
  bool always_resolve;
  bool resolve_all;
  char *dns_servers;

  /* Do IPv4 ARP or IPv6 ND scan of directly connected Ethernet hosts, even if
     non-ARP host discovery options are used? This is normally more efficient,
     not only because ARP/ND scan is faster, but because we need the MAC
     addresses provided by ARP or ND scan in order to do IP-based host discovery
     anyway. But when a network uses proxy ARP, all hosts will appear to be up
     unless you do an IP host discovery on them. This option is true by default. */
  bool implicitARPPing;

  // If true, write <os><osclass/><osmatch/></os> as in xmloutputversion 1.03
  // rather than <os><osmatch><osclass/></osmatch></os> as in 1.04 and later.
  bool deprecated_xml_osclass;

  bool traceroute;
  bool reason;
  bool adler32;
  FILE *excludefd;
  char *exclude_spec;
  FILE *inputfd;
  char *portlist; /* Ports list specified by user */
  char *exclude_portlist; /* exclude-ports list specified by user */

  // TODO nsock_proxychain proxy_chain;

#ifndef NOLUA
  bool script;
  char *scriptargs;
  char *scriptargsfile;
  bool scriptversion;
  bool scripttrace;
  bool scriptupdatedb;
  bool scripthelp;
  double scripttimeout;
  void chooseScripts(char* argument);
  std::vector<std::string> chosenScripts;
#endif

  /* ip options used in build_*_raw() */
  unsigned *ipoptions;
  int ipoptionslen;
  int ipopt_firsthop;	// offset in ipoptions where is first hop for source/strict routing
  int ipopt_lasthop;	// offset in ipoptions where is space for targets ip for source/strict routing

  // Statistics Options set in nmap.cc
  unsigned int numhosts_scanned;
  unsigned int numhosts_up;
  int numhosts_scanning;
  stype current_scantype;
  bool noninteractive;

  bool release_memory;	/* suggest to release memory before quitting. used to find memory leaks. */
 private:
  int max_os_tries;
  int max_rtt_timeout;
  int min_rtt_timeout;
  int initial_rtt_timeout;
  unsigned int max_retransmissions;
  unsigned int max_tcp_scan_delay;
  unsigned int max_udp_scan_delay;
  unsigned int max_sctp_scan_delay;
  unsigned int min_host_group_sz;
  unsigned int max_host_group_sz;
  void Initialize();
  int addressfamily; /*  Address family:  AF_INET or AF_INET6 */
  // TODOs struct sockaddr_storage sourcesock;
  size_t sourcesocklen;
  struct timeval start_time;
  bool pTrace; // Whether packet tracing has been enabled
  bool vTrace; // Whether version tracing has been enabled
  bool xsl_stylesheet_set;
  char *xsl_stylesheet;
  unsigned spoof_mac[6];
  bool spoof_mac_set;
};

#endif