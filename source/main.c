#include "hv_defeat_0304.h"
#include "hv_defeat_0506.h"
#include "hv_defeat_0607.h"

#include "loader.h"
#include "prepare_resume.h"
#include "utils.h"
#include <unistd.h>

int main(void) {
  if (setup_env()) {
    notify("Something went wrong while initiating.\nPlease make sure your fw "
           "is supported.");
    return -1;
  }

  if (fetch_linux(&linux_i)) {
    notify("Something went wrong while installing linux files.\n");
    return -1;
  }

  void *shellcode_kernel;
  size_t shellcode_kernel_len;

  if (prepare_resume(&shellcode_kernel, &shellcode_kernel_len)) {
    notify("Something went wrong while preparing resume.\n");
    return -1;
  }

  switch (fw) {

    case 0x0300 ... 0x04ff:
      if (hv_defeat_0304(shellcode_kernel, shellcode_kernel_len))
        goto err;
      break;

    case 0x0500 ... 0x064f:
      if (hv_defeat_0506(shellcode_kernel, shellcode_kernel_len))
        goto err;
      break;

    case 0x0650 ... 0x07ff:
      if (hv_defeat_0607(shellcode_kernel, shellcode_kernel_len))
        goto err;
      break;

    case 0x0940:
      if (hv_defeat_0607(shellcode_kernel, shellcode_kernel_len))
        goto err;
      break;

    default:
      goto err;
  }

  notify("Finished preparation. Going to rest mode in 5 seconds.\n"
         "Please wait for the orange light to stop blinking and then wakeup "
         "to Linux :)\n");

  sleep(5);
  enter_rest_mode();

  while (1) {
    sleep(30);
  }

  return 0;

err:
  notify("Something went wrong while defeating Hypervisor.\n"
         "Please make sure your fw is supported.");
  return -1;
}
