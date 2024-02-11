/*
 * Copyright (C) 2020 Inria
 * Copyright (C) 2020 Koen Zandberg <koen@bergzand.net>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "femtocontainer/femtocontainer.h"
#include "shared.h"
#include "xtimer.h"

#ifdef MODULE_GCOAP
#include "net/gcoap.h"
#include "net/nanocoap.h"
#endif
#include "fmt.h"
#include "log.h"
#include "saul.h"
#include "saul_reg.h"

#ifdef MODULE_ZTIMER
#include "ztimer.h"
#endif

uint32_t f12r_vm_memcpy(f12r_t *f12r, uint64_t *regs) {
  (void)f12r;

  void *dest = (void *)(uintptr_t)regs[1];
  const void *src = (const void *)(uintptr_t)regs[2];
  size_t len = (size_t)regs[3];

  return (uintptr_t)memcpy(dest, src, len);
}

#ifdef MODULE_SAUL_REG
uint32_t f12r_vm_saul_reg_find_nth(f12r_t *f12r, uint64_t *regs) {
  (void)f12r;
  int pos = (int)regs[1];
  saul_reg_t *reg = saul_reg_find_nth(pos);
  return (uint32_t)(intptr_t)reg;
}

uint32_t f12r_vm_saul_reg_find_type(f12r_t *f12r, uint64_t *regs) {
  (void)f12r;

  saul_reg_t *reg = saul_reg_find_type(regs[1]);
  return (uint32_t)(intptr_t)reg;
}

uint32_t f12r_vm_saul_reg_read(f12r_t *f12r, uint64_t *regs) {
  (void)f12r;

  saul_reg_t *dev = (saul_reg_t *)(intptr_t)regs[1];
  phydat_t *data = (phydat_t *)(intptr_t)regs[2];

  int res = saul_reg_read(dev, data);
  return (uint32_t)res;
}

uint32_t f12r_vm_saul_reg_write(f12r_t *f12r, uint64_t *regs) {
  (void)f12r;

  saul_reg_t *dev = (saul_reg_t *)(intptr_t)regs[1];
  phydat_t *data = (phydat_t *)(intptr_t)regs[2];

  LOG_DEBUG("bpf_vm_saul_reg_write: dev=%s, data=%d\n", dev->name,
            data->val[0]);
  int res = saul_reg_write(dev, data);
  return (uint32_t)res;
}
#endif

typedef bpf_coap_ctx_t f12r_coap_ctx_t;

#ifdef MODULE_GCOAP
// Those function calls are just broken.
// The femtocontainer VM calls the function by passing in the pointer to the
// array of registers and those expect that they will be called with a list of
// arguments.
uint32_t f12r_vm_gcoap_resp_init(f12r_t *f12r, uint64_t *regs) {
  (void)f12r;

  uint64_t coap_ctx_p = regs[1];
  uint64_t resp_code_u = regs[2];

  f12r_coap_ctx_t *coap_ctx = (f12r_coap_ctx_t *)(intptr_t)coap_ctx_p;
  unsigned resp_code = (unsigned)resp_code_u;

  gcoap_resp_init(coap_ctx->pkt, coap_ctx->buf, coap_ctx->buf_len, resp_code);
  return 0;
}

uint32_t f12r_vm_coap_add_format(f12r_t *f12r, uint64_t *regs) {
  (void)f12r;
  uint64_t coap_ctx_p = regs[1];
  uint64_t format = regs[2];

  f12r_coap_ctx_t *coap_ctx = (f12r_coap_ctx_t *)(intptr_t)coap_ctx_p;
  ssize_t res = coap_opt_add_format(coap_ctx->pkt, (uint16_t)format);
  return (uint32_t)res;
}

uint32_t f12r_vm_coap_opt_finish(f12r_t *f12r, uint64_t *regs) {
  (void)f12r;

  uint64_t coap_ctx_p = regs[1];
  uint64_t flags_u = regs[2];

  f12r_coap_ctx_t *coap_ctx = (f12r_coap_ctx_t *)(intptr_t)coap_ctx_p;
  uint16_t flags = (uint16_t)flags_u;

  ssize_t res = coap_opt_finish(coap_ctx->pkt, flags);
  return (uint32_t)res;
}

uint32_t f12r_vm_coap_get_pdu(f12r_t *f12r, uint64_t *regs) {
  (void)f12r;

  uint64_t coap_ctx_p = regs[1];

  f12r_coap_ctx_t *coap_ctx = (f12r_coap_ctx_t *)(intptr_t)coap_ctx_p;
  return (uint32_t)(intptr_t)((coap_pkt_t *)coap_ctx->pkt)->payload;
}
#endif

#ifdef MODULE_FMT
uint32_t f12r_vm_fmt_s16_dfp(f12r_t *f12r, uint64_t *regs) {
  (void)f12r;

  uint64_t out_p = regs[1];
  uint64_t val = regs[2];
  uint64_t fp_digits = regs[3];

  char *out = (char *)(intptr_t)out_p;
  size_t res = fmt_s16_dfp(out, (int16_t)val, (int)fp_digits);
  return (uint32_t)res;
}

uint32_t f12r_vm_fmt_u32_dec(f12r_t *f12r, uint64_t *regs) {
  (void)f12r;

  uint64_t out_p = regs[1];
  uint64_t val = regs[2];

  char *out = (char *)(intptr_t)out_p;
  size_t res = fmt_u32_dec(out, (uint32_t)val);
  return (uint32_t)res;
}
#endif

#ifdef MODULE_ZTIMER
uint32_t f12r_vm_ztimer_now(f12r_t *f12r, uint64_t *regs) {
  (void)f12r;
  (void)regs;
  return ztimer_now(ZTIMER_USEC);
}
uint32_t f12r_vm_ztimer_periodic_wakeup(f12r_t *f12r, uint64_t *regs) {
  (void)f12r;

  // TODO: figure out why f12r uses registers starting at 0 whereas the compiled
  // code puts the arument into the register 1
  /* Old code:
  uint32_t *last = (uint32_t*)(intptr_t)regs[0];

  ztimer_periodic_wakeup(ZTIMER_USEC, last, regs[1]);
  return 0;
  */
  // fixed:
  uint32_t *last = (uint32_t *)(intptr_t)regs[1];

  ztimer_periodic_wakeup(ZTIMER_USEC, last, regs[2]);
  return 0;
}
#endif

uint32_t f12r_vm_printf(f12r_t *f12r, uint64_t *regs) {
  (void)f12r;

  return printf((const char *)(intptr_t)regs[1], (uint32_t *)(intptr_t)regs[2],
                (uint32_t *)(intptr_t)regs[3], (uint32_t *)(intptr_t)regs[4],
                (uint32_t *)(intptr_t)regs[5]);
}

f12r_call_t f12r_get_external_call(uint32_t num) {
  switch (num) {
  case BPF_FUNC_BPF_PRINTF:
    return &f12r_vm_printf;
  case BPF_FUNC_BPF_MEMCPY:
    return &f12r_vm_memcpy;
#ifdef MODULE_SAUL_REG
  case BPF_FUNC_BPF_SAUL_REG_FIND_NTH:
    return &f12r_vm_saul_reg_find_nth;
  case BPF_FUNC_BPF_SAUL_REG_FIND_TYPE:
    return &f12r_vm_saul_reg_find_type;
  case BPF_FUNC_BPF_SAUL_REG_READ:
    return &f12r_vm_saul_reg_read;
  case BPF_FUNC_BPF_SAUL_REG_WRITE:
    return &f12r_vm_saul_reg_write;
#endif
#ifdef MODULE_GCOAP
  case BPF_FUNC_BPF_GCOAP_RESP_INIT:
    return &f12r_vm_gcoap_resp_init;
  case BPF_FUNC_BPF_COAP_OPT_FINISH:
    return &f12r_vm_coap_opt_finish;
  case BPF_FUNC_BPF_COAP_ADD_FORMAT:
    return &f12r_vm_coap_add_format;
  case BPF_FUNC_BPF_COAP_GET_PDU:
    return &f12r_vm_coap_get_pdu;
#endif
#ifdef MODULE_FMT
  case BPF_FUNC_BPF_FMT_S16_DFP:
    return &f12r_vm_fmt_s16_dfp;
  case BPF_FUNC_BPF_FMT_U32_DEC:
    return &f12r_vm_fmt_u32_dec;
#endif
#ifdef MODULE_ZTIMER
  case BPF_FUNC_BPF_ZTIMER_NOW:
    return &f12r_vm_ztimer_now;
  case BPF_FUNC_BPF_ZTIMER_PERIODIC_WAKEUP:
    return &f12r_vm_ztimer_periodic_wakeup;
#endif
  default:
    return NULL;
  }
}
