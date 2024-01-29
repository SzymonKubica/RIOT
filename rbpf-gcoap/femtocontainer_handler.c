#include "femtocontainer/femtocontainer.h"
#include "femtocontainer/shared.h"
#include "fmt.h"
#include "log.h"
#include "suit/storage.h"
#include "suit/storage/ram.h"
#include "suit/transport/coap.h"

static uint8_t _stack[512] = {0};
typedef struct {
  uint8_t *buf;
  size_t buf_len; /**< Packet buffer length */
} checksum_ctx_t;

static f12r_t _bpf = {
    .stack_region = NULL,
    .rodata_region = NULL,
    .data_region = NULL,
    .arg_region = NULL,
    .application = NULL,  /**< Application bytecode */
    .application_len = 0, /**< Application length */
    .stack = _stack,
    .stack_size = sizeof(_stack),
    .flags = FC_CONFIG_NO_RETURN,
    // TODO: set branches rem to something sensible
    .branches_remaining =
        100, /**< Number of allowed branch instructions remaining */
};

uint32_t execute_femtocontainer_vm(uint8_t *payload, size_t payload_len,
                                   char *location) {
  LOG_DEBUG("[BPF handler]: getting appropriate SUIT backend depending on the "
            "storage "
            "location id. \n");

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
    if (i % 8 == 7) {
      LOG_DEBUG("\n");
    }
  }
  LOG_DEBUG("\n");

  LOG_DEBUG("[BPF handler]: initialising the eBPF application struct\n");
  _bpf.application = mem_region;
  _bpf.application_len = length;

  f12r_mem_region_t mem_pkt;

  checksum_ctx_t bpf_ctx = {
      .buf = payload,
      .buf_len = payload_len,
  };

  // TODO: find out how to set the memory regions correctly
  LOG_DEBUG("[BPF handler]: payload length: %d\n", payload_len);
  f12r_add_region(&_bpf, &mem_pkt, payload, payload_len,
                  FC_MEM_REGION_READ | FC_MEM_REGION_WRITE);

  f12r_setup(&_bpf);
  int64_t result = -1;
  printf("[BPF handler]: executing VM\n");
  ztimer_acquire(ZTIMER_USEC);
  ztimer_now_t start = ztimer_now(ZTIMER_USEC);
  int res = f12r_execute_ctx(&_bpf, &bpf_ctx, sizeof(bpf_ctx), &result);
  ztimer_now_t end = ztimer_now(ZTIMER_USEC);
  uint32_t execution_time = end - start;

  printf("[BPF handler]: Execution complete res=%i, result=%d \nExecution "
         "time: %i [us]\n",
         res, (uint32_t)result, execution_time);

  return execution_time;
}
