#include "packet_sniffer.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>

ErrorCode handle_packet(const uint8_t* pkt_buffer, uint16_t pkt_length) {
	ErrorCode error_code = ERROR_SUCCESS;
	if (pkt_buffer == NULL) {
		error_code = ERROR_NULL_ARGUMENT;
		goto cleanup;
	}

	struct ethhdr* eth = (struct ethhdr*)pkt_buffer;
	if (ntohs(eth->h_proto) == ETH_P_IP) {
		struct iphdr* iph = (struct iphdr*)(pkt_buffer + sizeof(struct ethhdr));

		struct sockaddr_in src_ip = { 0 };
		src_ip.sin_addr.s_addr = iph->saddr;
		char src_ip_str[MAX_IP_LEN] = { 0 };
		strcpy(src_ip_str, inet_ntoa(src_ip.sin_addr)); 

		struct sockaddr_in dst_ip = { 0 };
		dst_ip.sin_addr.s_addr = iph->daddr;
		char dst_ip_str[MAX_IP_LEN] = { 0 };
		strcpy(dst_ip_str, inet_ntoa(dst_ip.sin_addr)); 

		printf("%s (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x) ---> %s (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x) ", src_ip_str,
			eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5], 
			dst_ip_str,
			eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	} else {
		printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x ---> %.2x:%.2x:%.2x:%.2x:%.2x:%.2x ",
			eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5], 
			eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	}
	printf("[%u]\n", pkt_length);

cleanup:
	return error_code;
}

ErrorCode sniff_packets(const char* interface_name) {
	ErrorCode error_code = ERROR_SUCCESS;
	ssize_t data_size;
	uint8_t packet_buffer[PACKET_BUFFER_SIZE] = { 0 };

	int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (raw_socket == -1) {
		perror("socket");
		error_code = ERROR_API;
		goto cleanup;
	}

	if (setsockopt(raw_socket, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name)) == -1) {
		perror("setsockopt");
		error_code = ERROR_API;
		goto cleanup;
	}

	for (;;) {
		data_size = recvfrom(raw_socket, packet_buffer, PACKET_BUFFER_SIZE, 0, NULL, NULL);
		if (data_size == -1) {
			perror("recvfrom");
			error_code = ERROR_API;
			goto cleanup;
		}

		error_code = handle_packet(packet_buffer, data_size);
		if (error_code != ERROR_SUCCESS) {
			printf("handle_packet failed with: %d\n", error_code);
			goto cleanup;
		}
	}

cleanup:
	if (raw_socket != -1 && close(raw_socket) == -1) {
		perror("close");
	}

	return error_code;
}