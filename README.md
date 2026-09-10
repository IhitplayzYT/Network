# Network Library

A low-level C networking library for constructing, sending, and receiving network packets at the Ethernet, IP, and ICMP layers.

## Overview

This library provides a comprehensive set of tools for network packet manipulation, including:
- ICMP echo request/reply (ping) functionality
- IP packet construction and parsing
- Ethernet frame creation and transmission
- MAC address manipulation and conversion
- Raw socket operations for Linux systems

## Why This Library

This library is designed for educational purposes and low-level network programming tasks where you need:
- Full control over packet headers at multiple network layers
- Understanding of network protocol internals
- Custom packet crafting for network testing and analysis
- Learning about network stack implementation details

## Dependencies

### System Requirements
- Linux operating system (uses Linux-specific socket headers)
- GCC compiler with C2x support
- Root/sudo privileges (required for raw socket operations)

### Build Dependencies
- Standard C library (libc)
- Linux kernel headers:
  - `arpa/inet.h` - Network address conversion
  - `sys/socket.h` - Socket API
  - `sys/types.h` - System data types
  - `ifaddrs.h` - Interface address operations
  - `linux/if_ether.h` - Ethernet protocol definitions
  - `linux/if_packet.h` - Packet socket operations
  - `net/ethernet.h` - Ethernet header structures

## Installation

### Clone or Download
```bash
cd /path/to/Network
```

### Build
```bash
make
```

This will compile the source files and create the `Networks` executable.

### Clean Build Artifacts
```bash
make clean
```

## Usage

### Running the Ethernet Frame Sender

The main program sends custom Ethernet frames with IP payloads:

```bash
sudo ./Networks <INTERFACE> <SRC_MAC> <DST_MAC> <SRC_IP> <DST_IP> <MSSG> <MSSG_LEN>
```

#### Parameters:
- `INTERFACE` - Network interface name (e.g., `eth0`, `wlan0`)
- `SRC_MAC` - Source MAC address (format: `AA:BB:CC:DD:EE:FF` or `AABB.CCDD.EEFF`)
- `DST_MAC` - Destination MAC address
- `SRC_IP` - Source IP address (format: `192.168.1.1`)
- `DST_IP` - Destination IP address
- `MSSG` - Message payload to send
- `MSSG_LEN` - Length of message (optional, defaults to message length)

#### Example:
```bash
sudo ./Networks eth0 00:11:22:33:44:55 66:77:88:99:AA:BB 192.168.1.100 192.168.1.1 "Hello" 5
```

### Using as a Library

Include the header in your C program:
```c
#include "Networks.h"
```

Compile with the object files:
```bash
gcc -o your_program your_program.c Networks.o helper.o constructor.o
```

## API Reference

### Core Data Structures

#### IP Packet
```c
typedef struct s_ip {
    i32 srcaddr;      // Source IP address (packed)
    i32 dstaddr;      // Destination IP address (packed)
    i16 id;           // Packet ID
    Type type:3;      // Protocol type (ICMP, TCP, UDP, Raw)
    Layer payload;    // Payload data
} Ip;
```

#### ICMP Packet
```c
typedef struct s_icmp {
    Type type:3;      // ICMP type (echo, echo_reply)
    i16 size;         // Payload size
    i8 *header;       // ICMP header data
} Icmp;
```

#### Ethernet Frame
```c
typedef struct s_ether {
    EtherType protocol; // Ethernet type (IP, ARP)
    Mac src, dst;       // Source and destination MAC addresses
    Ip* payload;        // IP payload
} Ethernet;
```

#### MAC Address
```c
typedef struct s_mac {
    i8 addr[6];        // 6-byte MAC address
} Mac;
```

### Key Functions

#### IP Operations
- `Ip *init_ip(Type type, i8 *src, i8 *dst, i16 id)` - Create IP packet
- `Bytestr *eval_ip(Ip *ip)` - Serialize IP packet to bytes
- `void show_ip(Ip *ip, i8 flag)` - Display IP packet information
- `i32 ipaddr(i8 *ipstr)` - Convert IP string to packed integer
- `i8 *ipstr(i32 addr)` - Convert packed integer to IP string

#### ICMP Operations
- `Icmp *init_icmp(Type type, i8 *data, i16 size)` - Create ICMP packet
- `Bytestr *eval_icmp(Icmp *icmp)` - Serialize ICMP packet to bytes
- `void show_icmp(Icmp *icmp, i8 flag)` - Display ICMP packet information
- `i8 _sendping(i8 *src, i8 *dst, i8 *mssg, i16 len)` - Send ICMP echo request

#### Ethernet Operations
- `Ethernet *init_ether(Mac *src, Mac *dst, EtherType type)` - Create Ethernet frame
- `Bytestr *eval_ether(Ethernet *ether)` - Serialize Ethernet frame to bytes
- `void show_ether(Ethernet *pkt, i8 flag)` - Display Ethernet frame information
- `i32 setup_ether_sock(i8 *interface, Mac *srcmac)` - Setup Ethernet socket
- `int _sendether(i32 sock, Ethernet *eth)` - Send Ethernet frame

#### MAC Address Operations
- `Mac *to_macs(i8 *str)` - Convert MAC string to Mac struct
- `Mac *to_mac(i64 arg)` - Convert packed integer to Mac struct
- `i8 *mac2str(Mac *mac)` - Convert Mac struct to string
- `i8 *mac2strf(Mac *mac)` - Convert Mac struct to formatted string
- `void show_mac(Mac *m, i8 x)` - Display MAC address

#### Utility Functions
- `i16 checksum(i8 *str, i16 size)` - Calculate internet checksum
- `void print_hex(void *ptr, i32 n)` - Print hex dump of memory
- `void freeall(void *first, ...)` - Free multiple pointers
- `i16 iftoidx(i8 *interface)` - Get interface index from name

## Examples

### Sending a Ping (ICMP Echo Request)

```c
#include "Networks.h"

int main() {
    init(); // Initialize with sudo check
    
    char *src = "192.168.1.100";
    char *dst = "8.8.8.8";
    char *message = "Hello";
    int len = 5;
    
    i8 result = sendping(src, dst, message, len);
    if (result == 0) {
        printf("Ping successful\n");
    } else {
        printf("Ping failed with error %d\n", result);
    }
    
    return 0;
}
```

### Creating and Sending an IP Packet

```c
#include "Networks.h"

int main() {
    init();
    
    // Create IP packet
    Ip *ip = init_ip(ICMP, "192.168.1.100", "8.8.8.8", 0);
    if (!ip) {
        fprintf(stderr, "Failed to create IP packet\n");
        return -1;
    }
    
    // Create ICMP payload
    char data[] = "Hello";
    Icmp *icmp = init_icmp(echo, data, sizeof(data));
    if (!icmp) {
        free(ip);
        return -1;
    }
    
    ip->payload.ip_pkt = icmp;
    
    // Setup socket and send
    i32 sock = setup_ip_sock();
    if (!sock) {
        FREE(ip, icmp);
        return -1;
    }
    
    int result = send_ip(sock, ip);
    printf("Send result: %d\n", result);
    
    close(sock);
    FREE(ip, icmp);
    return 0;
}
```

### Creating an Ethernet Frame

```c
#include "Networks.h"

int main() {
    init();
    
    // Create MAC addresses
    Mac *src = to_macs("00:11:22:33:44:55");
    Mac *dst = to_macs("AA:BB:CC:DD:EE:FF");
    
    // Create Ethernet frame
    Ethernet *ether = init_ether(src, dst, e_IP);
    if (!ether) {
        FREE(src, dst);
        return -1;
    }
    
    // Create IP payload
    Ip *ip = init_ip(Raw, "192.168.1.100", "192.168.1.1", 0);
    if (!ip) {
        FREE(src, dst, ether);
        return -1;
    }
    
    ether->payload = ip;
    
    // Setup socket and send
    i32 sock = setup_ether_sock("eth0", src);
    if (!sock) {
        FREE(src, dst, ether, ip);
        return -1;
    }
    
    int result = _sendether(sock, ether);
    printf("Send result: %d\n", result);
    
    close(sock);
    FREE(src, dst, ether, ip);
    return 0;
}
```

## Architecture

### File Structure
- `Networks.h` - Header file with type definitions, macros, and function declarations
- `Networks.c` - Main program and initialization
- `constructor.c` - Constructor functions for data structures
- `helper.c` - Helper functions for packet manipulation and conversion
- `Makefile` - Build configuration

### Layer Architecture
```
Application Layer
       ↓
Ethernet Layer (init_ether, eval_ether, show_ether)
       ↓
IP Layer (init_ip, eval_ip, show_ip)
       ↓
ICMP Layer (init_icmp, eval_icmp, show_icmp)
       ↓
Raw Socket Layer (setup_ip_sock, setup_ether_sock)
```

## Important Notes

### Privileges
This library requires root/sudo privileges because:
- Raw socket creation requires CAP_NET_RAW capability
- Packet header manipulation needs elevated permissions
- Network interface operations need admin access

Always run with sudo:
```bash
sudo ./Networks <arguments>
```

### Platform Limitations
- Linux-specific (uses Linux socket headers)
- Requires C2x compatible compiler
- Not portable to Windows or macOS without significant modifications

### Error Handling
Functions return NULL or 0 on failure. Always check return values:
```c
Ip *ip = init_ip(...);
if (!ip) {
    // Handle error
}
```

## Troubleshooting

### "Run with sudo" Error
The library checks for root privileges. Run with sudo:
```bash
sudo ./Networks <arguments>
```

### Socket Creation Failed
- Ensure you're running as root
- Check that the network interface exists: `ip link show`
- Verify firewall rules aren't blocking raw sockets

### Interface Not Found
- List available interfaces: `ip link show` or `ifconfig`
- Use the correct interface name (e.g., `eth0`, `wlan0`, `ens33`)

### MAC Address Format
Supported formats:
- Colon-separated: `AA:BB:CC:DD:EE:FF`
- Dot-separated: `AABB.CCDD.EEFF`

## License

This is an educational project. Use responsibly and in accordance with your local laws and network policies.

## Contributing

This is a learning project. Feel free to:
- Fix bugs
- Add new protocol support
- Improve documentation
- Enhance error handling

## Safety Warning

This library operates at the network layer and can:
- Send arbitrary network packets
- Potentially bypass network security measures
- Be used for network reconnaissance

Use only on networks you own or have explicit permission to test. Misuse may be illegal in your jurisdiction.
