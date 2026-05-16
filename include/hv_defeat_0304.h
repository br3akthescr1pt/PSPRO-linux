#ifndef HV_DEFEAT_0304_H
#define HV_DEFEAT_0304_H

#include "iommu.h"

int hv_defeat_0304(void);
int stage1_tmr_relax(void);
int iommu_selftest(void);
int stage2_patch_vmcbs(void);
int stage3_force_vmcb_reload(void);
int stage4_remove_xotext(void);
int stage5_kernel_pmap_invalidate_all(void);
int stage6_install_kexec(void);

#endif
