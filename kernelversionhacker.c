#include <stdio.h>
#include <mach/mach.h>
#include <sys/utsname.h>
#include <stdlib.h>

#ifdef __arm64__
#define IMAGE_OFFSET 0x2000
#define MACHO_HEADER_MAGIC 0xfeedfacf
#define MAX_KASLR_SLIDE 0x21000000
#define KERNEL_SEARCH_ADDRESS_IOS10 0xfffffff007004000
#define KERNEL_SEARCH_ADDRESS_IOS9 0xffffff8004004000
#define KERNEL_SEARCH_ADDRESS_IOS 0xffffff8000000000
#else
#define IMAGE_OFFSET 0x1000
#define MACHO_HEADER_MAGIC 0xfeedface
#define KERNEL_SEARCH_ADDRESS_IOS 0x81200000
#define KERNEL_SEARCH_ADDRESS_IPHONEOS 0xC0000000
#endif

#define ptrSize sizeof(uintptr_t)

task_t get_kernel_task() {
    task_t kt = 0;
    kern_return_t r = task_for_pid(mach_task_self(), 0, &kt);
    
    if (r) {
        r = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kt);
        if (r) {
            printf("task_for_pid and host_get_special_port failed\n");
            exit(-1);
        }
    }
    
    return kt;
}

static vm_address_t get_kernel_base(task_t kernel_task, uint64_t osRelease) {
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    
    uintptr_t addr = 0;
    
#ifdef __arm__
    if (osRelease <= 10) {
        addr = KERNEL_SEARCH_ADDRESS_IPHONEOS;
        return addr;
    }
    else {
        addr = KERNEL_SEARCH_ADDRESS_IOS;
    }
#elif __arm64__
    addr = KERNEL_SEARCH_ADDRESS_IOS;
#endif
    
    while (1) {
        
        char *buf;
        mach_msg_type_number_t sz = 0;
        if (KERN_SUCCESS != vm_region_recurse_64(kernel_task, (vm_address_t *)&addr, &size, &depth, (vm_region_info_t) &info, &info_count)) {
            continue;
        }
        
        if ((size > 1024*1024*1024)) {
            /*
             * https://code.google.com/p/iphone-dataprotection/
             * hax, sometimes on iOS7 kernel starts at +0x200000 in the 1Gb region
             */
            pointer_t buf;
            mach_msg_type_number_t sz = 0;
            addr += 0x200000;
            
            vm_read(kernel_task, addr + IMAGE_OFFSET, 512, &buf, &sz);
            if (*((uint32_t *)buf) != MACHO_HEADER_MAGIC) {
                addr -= 0x200000;
                vm_read(kernel_task, addr + IMAGE_OFFSET, 512, &buf, &sz);
                if (*((uint32_t*)buf) != MACHO_HEADER_MAGIC) {
                    break;
                }
            }
            
            return addr+IMAGE_OFFSET;
        }
        addr+=size;
    }
    printf("ERROR: Failed to find kernel base.\n");
    exit(1);
}

#ifdef __arm64__
static vm_address_t get_kernel_baseios9plus(mach_port_t kernel_task, uint64_t osRelease) {
    uint64_t addr = 0;
    
    /* iOS 10 and 11 share the same default kernel slide */
    if (osRelease == 16 || osRelease == 17) {
        addr = KERNEL_SEARCH_ADDRESS_IOS10+MAX_KASLR_SLIDE;
    }
    
    else if (osRelease == 15) {
        addr = KERNEL_SEARCH_ADDRESS_IOS9+MAX_KASLR_SLIDE;
    }
    
    else if (osRelease >= 18) {
        printf("This is an unknown kernel version, trying iOS 10/11 default address. If you panic, this is probably the cause\n");
        addr = KERNEL_SEARCH_ADDRESS_IOS10+MAX_KASLR_SLIDE;
    }
    
    /* This function shouldn't be getting called on iOS 8 or lower */
    else return -1;
    
    while (1) {
        char *buf;
        mach_msg_type_number_t sz = 0;
        kern_return_t ret = vm_read(kernel_task, addr, 0x200, (vm_offset_t*)&buf, &sz);
        
        if (ret) {
            goto next;
        }
        
        if (*((uint32_t *)buf) == MACHO_HEADER_MAGIC) {
            int ret = vm_read(kernel_task, addr, 0x1000, (vm_offset_t*)&buf, &sz);
            if (ret != KERN_SUCCESS) {
                printf("Failed vm_read %i\n", ret);
                goto next;
            }
            
            for (uintptr_t i=addr; i < (addr+0x2000); i+=(ptrSize)) {
                mach_msg_type_number_t sz;
                int ret = vm_read(kernel_task, i, 0x120, (vm_offset_t*)&buf, &sz);
                
                if (ret != KERN_SUCCESS) {
                    printf("Failed vm_read %i\n", ret);
                    exit(-1);
                }
                if (!strcmp(buf, "__text") && !strcmp(buf+0x10, "__PRELINK_TEXT")) {
                    return addr;
                }
            }
        }
        
    next:
        addr -= 0x200000;
    }
    
    printf("ERROR: Failed to find kernel base.\n");
    exit(1);
}
#endif

#define DEFAULT_VERSION_STRING "hacked"

int updateVersionString(char *newVersionString) {
    uintptr_t versionPtr = 0;
    struct utsname u = {0};
    uname(&u);
    
    mach_port_t kernel_task = get_kernel_task();
    
    vm_address_t kernel_base;
    
    uint64_t osRelease = strtol(u.release, NULL, 0);
#ifdef __arm64__
    if (osRelease >= 15) {
        kernel_base = get_kernel_baseios9plus(kernel_task, osRelease);
    }
    else  {
        kernel_base = get_kernel_base(kernel_task, osRelease);
    }
#elif __arm__
    kernel_base = get_kernel_base(kernel_task, osRelease);
#endif
    
    uintptr_t darwinTextPtr = 0;
    
    char *buf;
    
    vm_size_t sz;
    uintptr_t TEXT_const = 0;
    uint32_t sizeofTEXT_const = 0;
    uintptr_t DATA_data = 0;
    uint32_t sizeofDATA_data = 0;
    
    char *sectName;
#ifdef __arm__
    /* iOS 4 and below have the kernel version text in __TEXT_cstring */
    if (osRelease <= 11) {
        sectName = "__cstring";
    }
    else sectName = "__const";
#elif __arm64__
    sectName = "__const";
#endif
    
    for (uintptr_t i=kernel_base; i < (kernel_base+0x2000); i+=(ptrSize)) {
        int ret = vm_read(kernel_task, i, 0x150, (vm_offset_t*)&buf, (mach_msg_type_number_t*)&sz);
        if (ret != KERN_SUCCESS) {
            printf("Failed vm_read %i\n", ret);
            exit(-1);
        }
        
        if (!strcmp(buf, sectName) && !strcmp(buf+0x10, "__TEXT")) {
            TEXT_const = *(uintptr_t*)(buf+0x20);
            sizeofTEXT_const = *(uintptr_t*)(buf+(0x20 + ptrSize));
            
        }
        
        else if (!strcmp(buf, "__data") && !strcmp(buf+0x10, "__DATA")) {
            DATA_data = *(uintptr_t*)(buf+0x20);
            sizeofDATA_data = *(uintptr_t*)(buf+(0x20 + ptrSize));
        }
        
        if (TEXT_const && sizeofTEXT_const && DATA_data && sizeofDATA_data)
            break;
    }
    
    if (!(TEXT_const && sizeofTEXT_const && DATA_data && sizeofDATA_data)) {
        printf("Error parsing kernel macho\n");
        return -1;
    }
    
    for (uintptr_t i = TEXT_const; i < (TEXT_const+sizeofTEXT_const); i += 2)
    {
        int ret = vm_read_overwrite(kernel_task, i, strlen("Darwin Kernel Version"), (vm_address_t)buf, &sz);
        if (ret != KERN_SUCCESS) {
            printf("Failed vm_read %i\n", ret);
            return -1;
        }
        if (!memcmp(buf, "Darwin Kernel Version", strlen("Darwin Kernel Version"))) {
            darwinTextPtr = i;
            break;
        }
    }
    
    if (!darwinTextPtr) {
        printf("Error finding Darwin text\n");
        return -1;
    }
    
    uintptr_t versionTextXref[ptrSize];
    versionTextXref[0] = darwinTextPtr;
    
    for (uintptr_t i = DATA_data; i < (DATA_data+sizeofDATA_data); i += ptrSize) {
        int ret = vm_read_overwrite(kernel_task, i, ptrSize, (vm_address_t)buf, &sz);
        if (ret != KERN_SUCCESS) {
            printf("Failed vm_read %i\n", ret);
            return -1;
        }
        
        if (!memcmp(buf, versionTextXref, ptrSize)) {
            versionPtr = i;
            break;
        }
    }
    
    if (!versionPtr) {
        printf("Error finding _version pointer, did you already patch it?\n");
        return -1;
    }
    
    kern_return_t ret;
    vm_address_t newStringPtr = 0;
    vm_allocate(kernel_task, &newStringPtr, strlen(newVersionString), VM_FLAGS_ANYWHERE);
    
    ret = vm_write(kernel_task, newStringPtr, (vm_offset_t)newVersionString, strlen(newVersionString));
    if (ret != KERN_SUCCESS) {
        printf("Failed vm_write %i\n", ret);
        exit(-1);
    }
    
    ret = vm_write(kernel_task, versionPtr, (vm_offset_t)&newStringPtr, ptrSize);
    if (ret != KERN_SUCCESS) {
        printf("Failed vm_write %i\n", ret);
        return -1;
    }
    else {
        memset(&u, 0x0, sizeof(u));
        uname(&u);
        return 0;
    }
}

int main(int argc, char **argv, char **envp) {
    
    if (argc >= 2) {
        if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
            printf("Usage: kernelversionhacker (version string)\n");
            return 0;
        }
        if (strlen(argv[1]) > 0xff) {
            printf("New kernel version string must be 255 characters or less\n");
            return -1;
        }
    }
    
    struct utsname u = {0};
    uname(&u);
    
    int ret = 0;
    int tries=0;
    
    printf("Hacking kernel version...\n");
    
retry:
    
    tries++;
    
    if (tries > 5) {
        printf("Failed to HACK kernel\n");
        return -1;
    }
    
    if (argc >= 2)
        ret = updateVersionString(argv[1]);
    else ret = updateVersionString(DEFAULT_VERSION_STRING);
    
    memset(&u, 0x0, sizeof(u));
    
    if (ret) {
        return -1;
    }
    
    uname(&u);

    if (argc >= 2) {
        if (strcmp(u.version, argv[1])) {
            memset(&u, 0x0, sizeof(u));
            goto retry;
        }
    }
    
    else {
        if (strcmp(u.version, DEFAULT_VERSION_STRING)) {
            memset(&u, 0x0, sizeof(u));
            goto retry;
        }
    }
    
    printf("Kernel version HACKED\n");
    return 0;
}
