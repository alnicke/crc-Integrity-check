#include <windows.h>
#include <iostream>
#include <thread>
#include <fstream>
#include <iomanip>
#include <vector>
#include <array>
#include <atomic>
#include <chrono>
#include "lazyimporter.hpp"
void corrupt_text_section() { // you can use this function as an exit(0) or __fastfail(0) alternative.
    HMODULE module = GetModuleHandle(NULL);
    if (!module) return;
    IMAGE_DOS_HEADER* dos_headers = (IMAGE_DOS_HEADER*)module;
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)dos_headers + dos_headers->e_lfanew);
    IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt_headers);
    for (unsigned int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section_header++) {
        BYTE* section_addr = (BYTE*)module + section_header->VirtualAddress;
        SIZE_T section_size = section_header->Misc.VirtualSize ? section_header->Misc.VirtualSize : section_header->SizeOfRawData;
        DWORD old_prot;
        if (LI_FN(VirtualProtect).safe()(section_addr, section_size, PAGE_READWRITE, &old_prot)) {
            for (SIZE_T j = 0; j < section_size; j++) {
                section_addr[j] = rand() % 256;
            }
            LI_FN(VirtualProtect).safe()(section_addr, section_size, old_prot, &old_prot);
        }
    }
}
constexpr size_t CRC_TABLE_SIZE = 256; // size 256 bt
std::array<uint32_t, CRC_TABLE_SIZE> crc_table;
void initialize_crc_table() { // first initialzation
    const uint32_t polynomial = 0xEDB88320;
    for (uint32_t i = 0; i < CRC_TABLE_SIZE; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ (polynomial & (-(static_cast<int32_t>(crc & 1))));
        }
        crc_table[i] = crc;
    }
}
uint32_t crc32(const std::vector<uint8_t>& data) { // calc
    uint32_t crc = 0xFFFFFFFF;
    for (auto byte : data) {
        uint8_t index = static_cast<uint8_t>(crc ^ byte);
        crc = (crc >> 8) ^ crc_table[index];
    }
    return ~crc;
}
std::vector<uint8_t> textsection() { // get .text section, why .text because the valid executable's first section is .text, whatever.. it'll get it to calc the hash for comparison.
    HMODULE module = GetModuleHandle(NULL);
    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(module) + dos_header->e_lfanew);
    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);
    std::vector<uint8_t> section_data(section_header->SizeOfRawData);
    std::memcpy(
        section_data.data(),
        reinterpret_cast<uint8_t*>(module) + section_header->PointerToRawData,
        section_header->SizeOfRawData
    );
    return section_data;
}
// PoC usage
void crc_check(std::atomic<bool>& loop) {
    HMODULE module = GetModuleHandle(NULL);
    auto orig_section = textsection(); // getting first section
    uint32_t last_crc = crc32(orig_section); // calculating it
    while (loop) {
        try {
            auto curr_section = textsection();
            uint32_t curr_crc = crc32(curr_section);
            if (curr_crc != last_crc) { // mismatched
                std::cerr << "[*BAD] CRC change detected!" << std::endl; // informing the user about change and mismatch.
                for (size_t i = 0; i < orig_section.size(); ++i) {
                    if (orig_section[i] != curr_section[i]) {
                        uint8_t* modif_address = reinterpret_cast<uint8_t*>(module) +
                            IMAGE_FIRST_SECTION(reinterpret_cast<PIMAGE_NT_HEADERS>(
                                reinterpret_cast<uint8_t*>(module) + reinterpret_cast<PIMAGE_DOS_HEADER>(module)->e_lfanew))->PointerToRawData + i;
                        std::cout << "[*BAD] mismatch at address: 0x" << std::hex << reinterpret_cast<uintptr_t>(modif_address) // hacked address.
                            << " old value: 0x" << std::hex << static_cast<int>(orig_section[i])
                            << " new value: 0x" << std::hex << static_cast<int>(curr_section[i]) << std::endl;
                    }
                }
                last_crc = curr_crc;
                orig_section = curr_section;
            }
            else { // it matched.No hacked addresses,clean crc.
                std::cout << "[*GOOD] CRC is ok: 0x" << std::hex << curr_crc << std::endl; //  informing user that is CRC is ok.
            }
        }
        catch (const std::exception& e) {
            exit(0); // error 
        }
        std::this_thread::sleep_for(std::chrono::seconds(2)); // prevent high cpu usage with adding 2 second delay.
    }
}
