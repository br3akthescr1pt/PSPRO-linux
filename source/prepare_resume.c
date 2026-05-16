#include "prepare_resume.h"
#include "../shellcode_kernel/shellcode_kernel.h"
#include "../shellcode_kernel/shellcode_kernel_args.h"
#include "config.h"
#include "iommu.h"
#include "offsets.h"
#include "utils.h"
#include <stdio.h>

int prepare_resume(void) {
  if (env_offset.KERNEL_CODE_CAVE == 0) {
    printf("Error: missing code cave offset\n");
    return -1;
  }

  uint64_t args_va = prepare_sck_args();
  if (update_sck_args_ptr((uint64_t)shellcode_kernel_bin, args_va))
    return -1;

  uint64_t sck_va = ktext + env_offset.KERNEL_CODE_CAVE;
  kwrite_large(sck_va, shellcode_kernel_bin, shellcode_kernel_bin_len);

  hook_call_near(ktext + env_offset.HOOK_ACPI_WAKEUP_MACHDEP, sck_va);

  kwrite8(ktext + env_offset.KERNEL_DEBUG_PATCH, 0xC3);
  kwrite8(ktext + env_offset.KERNEL_CFI_CHECK, 0xC3);

  // Unmute uart.
  kwrite32(pa_to_dmap(0xC0115110), 0);

  return 0;
}

int update_sck_args_ptr(uint64_t shellcode, uint64_t args) {
  // Find the address 0x11AA11AA11AA11AA used as marker
  int offset = -1;
  for (uint64_t i = 0; i < 0x40; i++) {
    if (*(uint64_t *)(shellcode + i) == 0x11AA11AA11AA11AA) {
      offset = i;
      break;
    }
  }
  if (offset == -1) {
    notify("Could not find offset of args_ptr address - Aborting\n");
    return -1;
  }
  *(uint64_t *)(shellcode + offset) = args;
  return 0;
}

void hook_call_near(uint64_t hook, uint64_t dst) {
  int64_t diff_call = dst - hook;
  uint8_t new_instr[5];
  new_instr[0] = 0xE8;
  *((uint32_t *)&new_instr[1]) = (int32_t)(diff_call - 5);
  kernel_copyin(new_instr, hook, 5);
  DEBUG_PRINT("Instruction patched\n");
}

uint64_t prepare_sck_args(void) {
  shellcode_kernel_args args;
  args.fw_version = fw;
  args.ktext = ktext;
  args.kdata = kdata;
  args.dmap_base = dmap;

  args.fun_printf = ktext + env_offset.FUN_PRINTF;
  args.fun_hv_iommu_set_buffers = ktext + env_offset.FUN_HV_IOMMU_SET_BUFFERS;
  args.fun_hv_iommu_wait_completion =
      ktext + env_offset.FUN_HV_IOMM_WAIT_COMPLETION;
  args.fun_smp_rendezvous = ktext + env_offset.FUN_SMP_RENDEZVOUS;
  args.fun_smp_no_rendevous_barrier =
      ktext + env_offset.FUN_SMP_NO_RENDEVOUS_BARRIER;
  args.g_vbios = ktext + env_offset.G_VBIOS;

  args.fun_transmitter_control = ktext + env_offset.FUN_TRANSMITTER_CONTROL;
  args.fun_mp3_initialize = ktext + env_offset.FUN_MP3_INITIALIZE;
  args.fun_mp3_invoke = ktext + env_offset.FUN_MP3_INVOKE;

  args.iommu_mmio_va = iommu->mmio_va;
  args.iommu_cb2_va = iommu->cb2_base;
  args.iommu_cb3_va = iommu->cb3_base;
  args.iommu_eb_va = iommu->eb_base;
  memcpy(&args.vmcb[0], &vmcb_pa[0], sizeof(args.vmcb[0]) * 16);

  args.kernel_uart_override = ktext + env_offset.KERNEL_UART_OVERRIDE;
  args.hv_handle_vmexit_pa = env_offset.HV_HANDLE_VMEXIT_PA;
  args.hv_code_cave_pa = env_offset.HV_CODE_CAVE_PA;

  args.linux_info_va = linux_i.linux_info;

  uint64_t args_cave = pa_to_dmap(alloc_page());
  kernel_copyin(&args, args_cave, sizeof(args));

  return args_cave;
}
