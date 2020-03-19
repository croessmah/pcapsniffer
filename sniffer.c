#include <stdlib.h>
#include <string.h>
#include "sniffer.h"

#include <stdio.h>


#if !defined(WPCAP) || !defined(HAVE_REMOTE)
#error "WPCAP and HAVE_REMOTE macro must be defined"
#endif //WPCAP and HAVE_REMOTE check

#include "pcap.h"


struct sniffer
{
    pcap_t * pcap;
    pcap_if_t * devices_list;
    pcap_if_t * device;
    pcap_addr_t * addr;
    sniffer_callback callback;
    void * user_data;
    int running;
    int error_code;
    char error_text[PCAP_ERRBUF_SIZE];
};


static struct sniffer g_stub;

static struct sniffer *
aux_copy_to_stub(
    struct sniffer * sniffer
)
{
    memcpy(&g_stub, sniffer, sizeof(struct sniffer));
    return &g_stub;
}


static pcap_addr_t *
aux_find_address(
    pcap_addr_t * a,
    uint32_t if_ip
)
{
    struct sockaddr_in addr;
    for (; a != NULL; a = a->next) {
        if (a->addr->sa_family == AF_INET) {
            memcpy(&addr, a->addr, sizeof(addr));
            if (if_ip == addr.sin_addr.S_un.S_addr) {
                break;
            }
        }
    }
    return a;
}

static pcap_if_t *
aux_find_device(
    struct sniffer * sniffer,
    uint32_t if_ip
)
{
    for (pcap_if_t * d = sniffer->devices_list; d; d = d->next) {
        pcap_addr_t * address = aux_find_address(d->addresses, if_ip);
        if (address) {
            sniffer->addr = address;
            sniffer->device = d;
            break;
        }
    }
    return sniffer->device;
}

static void
aux_sniffer_destroy(
    struct sniffer * sniffer
)
{
    if (sniffer->pcap) {
        pcap_close(sniffer->pcap);
        sniffer->pcap = NULL;
    }
    if (sniffer->devices_list) {
        pcap_freealldevs(sniffer->devices_list);
        sniffer->devices_list = NULL;
        sniffer->device = NULL;
        sniffer->addr = NULL;
    }
    sniffer->callback = NULL;
    sniffer->user_data = NULL;
    if (sniffer != &g_stub) {
        free(sniffer);
    }
}

static struct sniffer *
aux_allocate_and_copy(
    struct sniffer * sniffer
)
{
    struct sniffer * copy = malloc(sizeof(struct sniffer));
    if (copy) {
        memcpy(copy, sniffer, sizeof(struct sniffer));
    } else {
        sniffer->error_code = eSE_MEMORY_ALLOCATE_ERROR;
    }
    return copy;
}


static void
aux_packet_handler(
    u_char * user,
    struct pcap_pkthdr const * pkt_header,
    u_char const * pkt_data
)
{
    struct sniffer * sniffer = (struct sniffer *)user;
    sniffer->callback(pkt_data, pkt_header->len, sniffer->user_data);
}


static int
aux_start_loop(
    struct sniffer * sniffer
)
{
    return pcap_loop(sniffer->pcap, -1, aux_packet_handler, (u_char *)sniffer);
}



struct sniffer *
sniffer_create(
    uint32_t if_ip
)
{
    struct sniffer * result = NULL;
    struct sniffer sniffer;    
    memset(&sniffer, 0, sizeof(struct sniffer));
    if (-1 == pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &sniffer.devices_list, sniffer.error_text)) {
        sniffer.error_code = eSE_DEVICE_FIND_FAILED;
        goto DONE;
    }
    if (!aux_find_device(&sniffer, if_ip)) {
        sniffer.error_code = eSE_INTERFACE_NOT_FOUND;
        //todo: add interface ip to message
        strcpy(sniffer.error_text, "Interface not found");
        goto DONE;
    }
    sniffer.pcap = pcap_open_live(sniffer.device->name, 65535, 1, 100, sniffer.error_text);
    if (!sniffer.pcap) {
        sniffer.error_code = eSE_OPEN_DEVICE_FAILURE;
        goto DONE;
    }
    if (!sniffer.error_code) {
        result = aux_allocate_and_copy(&sniffer);
    }
DONE:
    if (sniffer.error_code) {
        result = aux_copy_to_stub(&sniffer);
        aux_sniffer_destroy(result);
    }
    return result;
}


struct sniffer *
sniffer_destroy(
    struct sniffer * sniffer
)
{
    if (sniffer->running) {
        sniffer_stop(sniffer);
    }
    aux_sniffer_destroy(sniffer);
    return NULL;
}


struct sniffer *
sniffer_start(
    struct sniffer * sniffer,
    sniffer_callback callback,
    void * data
)
{
    if (!sniffer) {
        return sniffer;
    }
    if (!callback) {
        sniffer->error_code = eSE_INVALID_ARGUMENT;
        strcpy(sniffer->error_text, "Callback not set");
        return sniffer;
    }

    if (!sniffer->pcap) {
        sniffer->error_code = eSE_INVALID_ARGUMENT;
        strcpy(sniffer->error_text, "Device not opened");
        return sniffer;
    }

    sniffer->callback = callback;
    sniffer->user_data = data;
    sniffer->running = 1;
    int ret = aux_start_loop(sniffer);
    sniffer->running = 0;
    if (ret == -2) {
        sniffer->error_code = eSE_SUCCESS;
        strcpy(sniffer->error_text, "Success");
    } else if (ret == -1) {
        sniffer->error_code = eSE_CAPTURE_ERROR;
        strcpy(sniffer->error_text, pcap_geterr(sniffer->pcap));
    } else if (ret == 0) {
        sniffer->error_code = eSE_CAPTURE_ERROR;
        strcpy(sniffer->error_text, "Invalid return value");
    }
    return sniffer;
}


void
sniffer_stop(
    struct sniffer * sniffer
)
{
    if (sniffer && sniffer->pcap) {
        pcap_breakloop(sniffer->pcap);
    }
}


char const *
sniffer_error_message(
    struct sniffer * sniffer
)
{
    return sniffer->error_text;
}


int
sniffer_error_code(
    struct sniffer * sniffer
)
{
    return sniffer->error_code;
}


int
sniffer_current_device_name(
    struct sniffer * sniffer,
    char * destination,
    unsigned size
)
{
    if (NULL == sniffer->device) {
        return -1;
    }

    unsigned name_length = strlen(sniffer->device->name);

    if (NULL == destination) {
        return name_length;
    }

    if (size == 0) {
        return -1;
    }

    unsigned copy_size = (name_length < size)? name_length: size - 1;
    memcpy(destination, sniffer->device->name, copy_size);
    destination[copy_size] = '\0';

    return copy_size;
}
