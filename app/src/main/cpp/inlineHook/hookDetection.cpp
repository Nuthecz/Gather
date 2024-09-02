//
// Created by NU on 2024/8/31.
//

#include "../include/hookDetection.h"
#include <zlib.h>
#include <fcntl.h>

// crc32 计算
uint32_t calculateCRC32(const unsigned char* data, size_t length){
    uint32_t crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, data, length);
    return crc;
}

void openHookStatus(){
    // 获取 libc open_offset
    SandHook::ElfImg libc("libc.so");
    void* open_addr = libc.getSymbAddress("open");
    uintptr_t open_offset = (uintptr_t)open_addr - (uintptr_t)libc.getBase();
    LOGI("open offset: 0x%x", open_offset);

    // 根据 open_offset 读取本地 libc open 的前16字节进行 CRC32 计算
    int fd = open(libc.name().c_str(), O_RDONLY);
    lseek(fd, open_offset, 0);
    char buf[16];
    read(fd, buf, 16);
    uintptr_t local_crc32_open_value = calculateCRC32(
            reinterpret_cast<const unsigned char*>(buf), 16);

    // 读取内存中的 open 前16字节进行 CRC32 计算
    uintptr_t mem_crc32_open_value = calculateCRC32(
            reinterpret_cast<const unsigned char*>(open_addr), 16);

    LOGI("local open crc32: 0x%x, mem open crc32: 0x%x", local_crc32_open_value, mem_crc32_open_value);
    if(local_crc32_open_value != mem_crc32_open_value){
        LOGE("open hook detected");
    }

}

void segmentHookStatus(){
    // 获取 libc text_offset
    SandHook::ElfImg libc("libc.so");
    auto text_info = libc.getTextSectionInfo();
    LOGI("text info: 0x%x, 0x%x", text_info.first, text_info.second);

    // 根据 text_offset 读取本地 libc text 进行 CRC32 计算
    int fd = open(libc.name().c_str(), O_RDONLY);
    lseek(fd, text_info.first, 0);
    char buf[text_info.second];
    read(fd, buf, text_info.second);
    uintptr_t local_crc32_text_value = calculateCRC32(
            reinterpret_cast<const unsigned char*>(buf), text_info.second);

    // 读取内存中的 text 进行 CRC32 计算
    uintptr_t text_addr = (uintptr_t)libc.getBase() + text_info.first;
    uintptr_t mem_crc32_text_value = calculateCRC32(
            reinterpret_cast<const unsigned char *>(text_addr), text_info.second);

    LOGI("local text crc32: 0x%x, mem text crc32 0x%x", local_crc32_text_value, mem_crc32_text_value);

    if(local_crc32_text_value != mem_crc32_text_value){
        LOGE("text hook detected");
    }

    // 获取 libc plt_offset
    auto plt_info = libc.getPltSectionInfo();
    LOGI("plt info: 0x%x, 0x%x", plt_info.first, plt_info.second);

    // 根据 plt_offset 读取本地 libc plt 进行 CRC32 计算
    lseek(fd, plt_info.first, 0);
    char buf2[plt_info.second];
    read(fd, buf2, plt_info.second);
    uintptr_t local_crc32_plt_value = calculateCRC32(
            reinterpret_cast<const unsigned char *>(buf2), plt_info.second);

    // 读取内存中的 plt 进行 CRC32 计算
    uintptr_t plt_addr = (uintptr_t)libc.getBase() + plt_info.first;
    uintptr_t mem_crc32_plt_value = calculateCRC32(
            reinterpret_cast<const unsigned char *>(plt_addr), plt_info.second);

    LOGI("local plt crc32: 0x%x, mem plt crc32 0x%x", local_crc32_plt_value, mem_crc32_plt_value);

    if(local_crc32_plt_value != mem_crc32_plt_value){
        LOGE("plt hook detected");
    }
    close(fd);
}

void prettyMethodHookStatus(){
    SandHook::ElfImg libart("libart.so");
    // 本地文件查找的
    // _ZN3art9ArtMethod12PrettyMethodEb
    // _ZN3art9ArtMethod12PrettyMethodEPS0_b

    // https://github1s.com/LSPosed/LSPlant/blob/master/lsplant/src/main/jni/art/runtime/art_method.cxx#L27
    // lsposed 源码中的，但是在测试中只有第一个可以找到相应的函数，所以还是需要与本地文件相结合来看
    // _ZN3art9ArtMethod12PrettyMethodEPS0_b
    // _ZN3art12PrettyMethodEPNS_9ArtMethodEb
    // _ZN3art12PrettyMethodEPNS_6mirror9ArtMethodEb
    std::array<const char*, 4> symbols = {
            "_ZN3art9ArtMethod12PrettyMethodEb",
            "_ZN3art9ArtMethod12PrettyMethodEPS0_b",
            "_ZN3art12PrettyMethodEPNS_9ArtMethodEb",
            "_ZN3art12PrettyMethodEPNS_6mirror9ArtMethodEb"
    };

    void * PrettyMethod_addr = nullptr;
    for (const auto& symbol : symbols) {
        PrettyMethod_addr = libart.getSymbAddress(symbol);
        if (PrettyMethod_addr != nullptr) {
            break;
        }
    }

    if (PrettyMethod_addr == nullptr) {
        LOGI("PrettyMethod not found");
    }

    uintptr_t PrettyMethod_offset = (uintptr_t)PrettyMethod_addr - (uintptr_t)libart.getBase();
    LOGI("PrettyMethod addr: 0x%x", PrettyMethod_offset);

    // 根据 PrettyMethod_offset 读取本地 libart PrettyMethod 的前16字节进行 CRC32 计算
    int fd = open(libart.name().c_str(), O_RDONLY);
    lseek(fd, PrettyMethod_offset, 0);
    char buf[16];
    read(fd, buf, 16);
    uintptr_t local_crc32_prettymethod_value = calculateCRC32(
            reinterpret_cast<const unsigned char*>(buf), 16);

    // 读取内存中的 PrettyMethod 前16字节进行 CRC32 计算
    uintptr_t mem_crc32_prettymethod_value = calculateCRC32(
            reinterpret_cast<const unsigned char*>(PrettyMethod_addr), 16);

    LOGI("local PrettyMethod crc32: 0x%x, mem PrettyMethod crc32: 0x%x", local_crc32_prettymethod_value, mem_crc32_prettymethod_value);
    if(local_crc32_prettymethod_value != mem_crc32_prettymethod_value){
        LOGE("PrettyMethod hook detected");
    }
}