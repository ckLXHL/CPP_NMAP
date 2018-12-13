#ifndef LOG_H
#define LOG_H

#include <string>
using std::string;
const int LOG_NUM_FILES = 4;  /* # of values that actual files (they must come first */
const int LOG_FILE_MASK = 15; /* The mask for log types in the file array */
const int LOG_NORMAL = 1;
const int LOG_MACHINE = 2;
const int LOG_SKID = 4;
const int LOG_XML = 8;
const int LOG_STDOUT = 1024;
const int LOG_STDERR = 2048;
const int LOG_SKID_NOXLT = 4096;
const int LOG_MAX = LOG_SKID_NOXLT; /* The maximum log type value */

const int LOG_PLAIN = (LOG_NORMAL | LOG_SKID | LOG_STDOUT);

const string LOG_NAMES[] = {"normal", "machine", "$Cr!pT |<!dd!3", "XML"};

const string PCAP_OPEN_ERRMSG = "Call to pcap_open_live() failed three times. "
                                "There are several possible reasons for this, depending on your operating "
                                "system:\nLINUX: If you are getting Socket type not supported, try "
                                "modprobe af_packet or recompile your kernel with PACKET enabled.\n "
                                "*BSD:  If you are getting device not configured, you need to recompile "
                                "your kernel with Berkeley Packet Filter support.  If you are getting "
                                "No such file or directory, try creating the device (eg cd /dev; "
                                "MAKEDEV <device>; or use mknod).\n*WINDOWS:  Nmap only supports "
                                "ethernet interfaces on Windows for most operations because Microsoft "
                                "disabled raw sockets as of Windows XP SP2.  Depending on the reason for "
                                "this error, it is possible that the --unprivileged command-line argument "
                                "will help.\nSOLARIS:  If you are trying to scan localhost or the "
                                "address of an interface and are getting '/dev/lo0: No such file or "
                                "directory' or 'lo0: No DLPI device found', complain to Sun.  I don't "
                                "think Solaris can support advanced localhost scans.  You can probably "
                                "use \"-Pn -sT localhost\" though.\n\n";

#include "scanLists.h"
//
//#include <nsock.h>
//class PortList;
//class Target;
//
//#include <stdarg.h>
//#include <string>
//
//#ifdef WIN32
///* Show a fatal error explaining that an interface is not Ethernet and won't
//   work on Windows. Do nothing if --send-ip (PACKET_SEND_IP_STRONG) was used. */
//void win32_fatal_raw_sockets(const char *devname);
//#endif
//
///* Prints the familiar Nmap tabular output showing the "interesting"
//   ports found on the machine.  It also handles the Machine/Grepable
//   output and the XML output.  It is pretty ugly -- in particular I
//   should write helper functions to handle the table creation */
//void printportoutput(Target *currenths, PortList *plist);
//
///* Prints the MAC address if one was found for the target (generally
//   this means that the target is directly connected on an ethernet
//   network.  This only prints to human output -- XML is handled by a
//   separate call ( print_MAC_XML_Info ) because it needs to be printed
//   in a certain place to conform to DTD. */
//void printmacinfo(Target *currenths);
//
//char *logfilename(const char *str, struct tm *tm);
//
///* Write some information (printf style args) to the given log stream(s).
//   Remember to watch out for format string bugs. */
//void log_write(int logt, const char *fmt, ...)
//     __attribute__ ((format (printf, 2, 3)));
//
///* This is the workhorse of the logging functions.  Usually it is
//   called through log_write(), but it can be called directly if you
//   are dealing with a vfprintf-style va_list.  Unlike log_write, YOU
//   CAN ONLY CALL THIS WITH ONE LOG TYPE (not a bitmask full of them).
//   In addition, YOU MUST SANDWICH EACH EXECUTION OF THIS CALL BETWEEN
//   va_start() AND va_end() calls. */
//void log_vwrite(int logt, const char *fmt, va_list ap);
//
///* Close the given log stream(s) */
//void log_close(int logt);
//
///* Flush the given log stream(s).  In other words, all buffered output
//   is written to the log immediately */
//void log_flush(int logt);
//
///* Flush every single log stream -- all buffered output is written to the
//   corresponding logs immediately */
//void log_flush_all();
//
///* Open a log descriptor of the type given to the filename given.  If
//   append is nonzero, the file will be appended instead of clobbered if
//   it already exists.  If the file does not exist, it will be created */
//int log_open(int logt, bool append, char *filename);
//
///* Output the list of ports scanned to the top of machine parseable
//   logs (in a comment, unfortunately).  The items in ports should be
//   in sequential order for space savings and easier to read output */
//void output_ports_to_machine_parseable_output(struct scan_lists *ports);
//
///* Return a std::string containing all n strings separated by whitespace, and
//   individually quoted if needed. */
//std::string join_quoted(const char * const strings[], unsigned int n);
//
///* Similar to output_ports_to_machine_parseable_output, this function
//   outputs the XML version, which is scaninfo records of each scan
//   requested and the ports which it will scan for */
//void output_xml_scaninfo_records(struct scan_lists *ports);
//
///* Writes a heading for a full scan report ("Nmap scan report for..."),
//   including host status and DNS records. */
//void write_host_header(Target *currenths);
//
///* Writes host status info to the log streams (including STDOUT).  An
//   example is "Host: 10.11.12.13 (foo.bar.example.com)\tStatus: Up\n" to
//   machine log. */
//void write_host_status(Target *currenths);
//
///* Prints the formatted OS Scan output to stdout, logfiles, etc (but only
//   if an OS Scan was performed */
//void printosscanoutput(Target *currenths);
//
///* Prints the alternate hostname/OS/device information we got from the
//   service scan (if it was performed) */
//void printserviceinfooutput(Target *currenths);
//
//#ifndef NOLUA
//std::string protect_xml(const std::string s);
//
///* Use this function to report NSE_PRE_SCAN and NSE_POST_SCAN results */
//void printscriptresults(ScriptResults *scriptResults, stype scantype);
//
//void printhostscriptresults(Target *currenths);
//#endif
//
///* Print a table with traceroute hops. */
//void printtraceroute(Target *currenths);
//
///* Print "times for host" output with latency. */
//void printtimes(Target *currenths);
//
///* Print a detailed list of Nmap interfaces and routes to
//   normal/skiddy/stdout output */
//int print_iflist(void);
//
///* Prints a status message while the program is running */
//void printStatusMessage();
//
//void print_xml_finished_open(time_t timep, const struct timeval *tv);
//
//void print_xml_hosts();
//
///* Prints the statistics and other information that goes at the very end
//   of an Nmap run */
//void printfinaloutput();
//
///* Prints the names of data files that were loaded and the paths at which they
//   were found. */
//void printdatafilepaths();
//
///* nsock logging interface */
//void nmap_adjust_loglevel(bool trace);
//void nmap_nsock_stderr_logger(const struct nsock_log_rec *rec);

#endif /* OUTPUT_H */
