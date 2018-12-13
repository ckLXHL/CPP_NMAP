#ifndef NMAP_OPS_H
#define NMAP_OPS_H

struct FingerPrintDB;
struct FingerMatch;
#include <string>
#include <chrono>

using std::string;
using std::chrono::seconds;
using std::chrono::duration;
using std::chrono::time_point;

class NmapOps {
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
};

#endif