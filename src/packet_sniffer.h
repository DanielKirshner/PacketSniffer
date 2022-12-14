#ifndef __PACKET_SNIFFER_H__
#define __PACKET_SNIFFER_H__

#include <stdint.h>

#define MAX_IP_LEN 16
#define PACKET_BUFFER_SIZE 65536

typedef enum {
	ERROR_SUCCESS = 0,
	ERROR_BAD_ARGUMENTS,
	ERROR_API,
	ERROR_NULL_ARGUMENT
} ErrorCode;

ErrorCode handle_packet(const uint8_t* pkt_buffer, uint16_t pkt_length);

ErrorCode sniff_packets(const char* interface_name);

#endif