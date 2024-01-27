
#include "suit/transport/coap.h"
#include <stdint.h>
#include <stdio.h>
#include "suit/storage.h"
#include "suit/storage/ram.h"
#include "suit/transport/coap.h"
#include "log.h"


#define MAIN_QUEUE_SIZE     (8)

static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];


void do_gnrc_msg_queue_init(void) {
    /* the shell contains commands that receive packets via GNRC and thus
       needs a msg queue */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    puts("GNRC msg queue initialized");
}

// Returs the number of bytes read
uint32_t load_suit_bytecode(uint8_t* buff, char *location)
{

    LOG_DEBUG("[BPF handler]: getting SUIT storage given id: %s. \n", location);

    suit_storage_t *storage = suit_storage_find_by_id(location);

    assert(storage);

    LOG_DEBUG("[BPF handler]: setting suit storage active location: %s\n",
           location);
    suit_storage_set_active_location(storage, location);
    const uint8_t *mem_region;
    size_t length;

    LOG_DEBUG("[BPF handler]: getting a pointer to the data stored in the SUIT "
           "location. \n");
    suit_storage_read_ptr(storage, &mem_region, &length);

    LOG_DEBUG("[BPF handler]: Application bytecode:\n");
    for (size_t i = 0; i < length; i++) {
        LOG_DEBUG("%02x", mem_region[i]);
        // Add a new line every 8x8 bits -> each eBPF instruction is 64 bits
        // long.
        *(buff + i) = mem_region[i];
        if (i % 8 == 7) {
            LOG_DEBUG("\n");
        }
    }
    LOG_DEBUG("\n");
    return length;
}

