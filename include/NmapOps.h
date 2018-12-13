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
#include <cstdlib>

using std::string;
using std::unordered_map;
using std::vector;
using std::chrono::duration;
using std::chrono::seconds;
using std::chrono::time_point;

class NmapOps
{
public:
  NmapOps();

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
  bool packetTrace() { return (debugging >= 3) ? true : pTrace; }

  bool isRoot = getenv("") ;
  bool have_pcap;
  unsigned debugging;
  bool resuming;
  int sendpref;

  // func

  bool packetTrace() { return (debugging >= 3) ? true : pTrace; }
  bool versionTrace() { return packetTrace() ? true : vTrace; }
#ifndef NOLUA
  bool scriptTrace()
  {
    return packetTrace() ? true : scripttrace;
  }
#endif
  // Note that packetTrace may turn on at high debug levels even if
  // setPacketTrace(false) has been called
  void setPacketTrace(bool pt) { pTrace = pt; }
  void setVersionTrace(bool vt) { vTrace = vt; }
  bool openOnly() { return open_only; }
  void setOpenOnly(bool oo) { open_only = oo; }
  unsigned verbose;
  /* The requested minimum packet sending rate, or 0.0 if unset. */
  float min_packet_send_rate;
  /* The requested maximum packet sending rate, or 0.0 if unset. */
  float max_packet_send_rate;
  /* The requested auto stats printing interval, or 0.0 if unset. */
  float stats_interval;
  bool randomize_hosts;
  bool randomize_ports;
  bool spoofsource; /* -S used */
  bool fastscan;
  char device[64];
  int ping_group_sz;
  bool nogcc;                   /* Turn off group congestion control with --nogcc */
  bool generate_random_ips;     /* -iR option */
  FingerPrintDB *reference_FPs; /* Used in the new OS scan system. */
  std::vector<FingerMatch> os_labels_ipv6;
  unsigned short magic_port; /* The source port set by -g or --source-port. */
  bool magic_port_set;       /* Was this set by user? */

  /* Scan timing/politeness issues */
  int timing_level;    // 0-5, corresponding to Paranoid, Sneaky, Polite, Normal, Aggressive, Insane
  int max_parallelism; // 0 means it has not been set
  int min_parallelism; // 0 means it has not been set
  double topportlevel; // -1 means it has not been set

  /* The maximum number of OS detection (gen2) tries we will make
     without any matches before giving up on a host.  We may well give
     up after fewer tries anyway, particularly if the target isn't
     ideal for unknown fingerprint submissions */
  int maxOSTries() { return max_os_tries; }
  void setMaxOSTries(int mot);

  /* These functions retrieve and set the Round Trip Time timeouts, in
   milliseconds.  The set versions do extra processing to insure sane
   values and to adjust each other to insure consistence (e.g. that
   max is always at least as high as min) */
  int maxRttTimeout() { return max_rtt_timeout; }
  int minRttTimeout() { return min_rtt_timeout; }
  int initialRttTimeout() { return initial_rtt_timeout; }
  void setMaxRttTimeout(int rtt);
  void setMinRttTimeout(int rtt);
  void setInitialRttTimeout(int rtt);
  void setMaxRetransmissions(int max_retransmit);
  unsigned int getMaxRetransmissions() { return max_retransmissions; }

  /* Similar functions for Host group size */
  int minHostGroupSz() { return min_host_group_sz; }
  int maxHostGroupSz() { return max_host_group_sz; }
  void setMinHostGroupSz(unsigned int sz);
  void setMaxHostGroupSz(unsigned int sz);
  unsigned int maxTCPScanDelay() { return max_tcp_scan_delay; }
  unsigned int maxUDPScanDelay() { return max_udp_scan_delay; }
  unsigned int maxSCTPScanDelay() { return max_sctp_scan_delay; }
  void setMaxTCPScanDelay(unsigned int delayMS) { max_tcp_scan_delay = delayMS; }
  void setMaxUDPScanDelay(unsigned int delayMS) { max_udp_scan_delay = delayMS; }
  void setMaxSCTPScanDelay(unsigned int delayMS) { max_sctp_scan_delay = delayMS; }

  /* Sets the Name of the XML stylesheet to be printed in XML output.
     If this is never called, a default stylesheet distributed with
     Nmap is used.  If you call it with NULL as the xslname, no
     stylesheet line is printed. */
  void setXSLStyleSheet(const char *xslname);
  /* Returns the full path or URL that should be printed in the XML
     output xml-stylesheet element.  Returns NULL if the whole element
     should be skipped */
  char *XSLStyleSheet();

  /* Sets the spoofed MAC address */
  void setSpoofMACAddress(unsigned *mac_data);
  /* Gets the spoofed MAC address, but returns NULL if it hasn't been set */
  const unsigned *spoofMACAddress() { return spoof_mac_set ? spoof_mac : NULL; }

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
  int extra_payload_length;     /* These two are for --data-length op */
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
  bool osscan_guess; /* Be more aggressive in guessing OS type */
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
  char *idleProxy; /* The idle host used to "Proxy" an idle scan */
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
  int ttl;           // Time to live
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
  char *portlist;         /* Ports list specified by user */
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
  void chooseScripts(char *argument);
  std::vector<std::string> chosenScripts;
#endif

  /* ip options used in build_*_raw() */
  unsigned *ipoptions;
  int ipoptionslen;
  int ipopt_firsthop; // offset in ipoptions where is first hop for source/strict routing
  int ipopt_lasthop;  // offset in ipoptions where is space for targets ip for source/strict routing

  // Statistics Options set in nmap.cc
  unsigned int numhosts_scanned;
  unsigned int numhosts_up;
  int numhosts_scanning;
  stype current_scantype;
  bool noninteractive;

  bool release_memory; /* suggest to release memory before quitting. used to find memory leaks. */
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