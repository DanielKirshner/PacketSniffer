#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PACKET_BUFFER_SIZE 65536 // for MTU=1500 bytes 

int main(int argc, char* argv[])
{
    int error_code = 0;
    ssize_t data_size;
    uint8_t packet_buffer[PACKET_BUFFER_SIZE];

    if(argc != 2)
    {
        printf("Usage %s [InterfaceName]\n", argv[0]);
        error_code = 1;
        goto cleanup;
    }

    const char* interface_name = argv[1];
    int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(raw_socket == -1)
    {
        perror("socket");
        error_code = 2;
        goto cleanup;
    }

    if(setsockopt(raw_socket, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name)) == -1 )
    {
        perror("setsockopt");
        error_code = 2;
        goto cleanup;
    }

cleanup:
    if(raw_socket != -1 && close(raw_socket) == -1)
    {
        perror("close");
    }
    return error_code;
}
