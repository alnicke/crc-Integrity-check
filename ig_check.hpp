// Integrity check by alnicke.
// https://github.com/alnicke/crc-Integrity-check/edit/main/ig_check.hpp
// Not removing this is appreciated.
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
void txtsec_unloader() { // you can use this function as an exit(0) or __fastfail(0) alternative.
    HMODULE selfmodule = GetModuleHandle(NULL);
    if (!selfmodule) return;
    IMAGE_DOS_HEADER* dos_headers = (IMAGE_DOS_HEADER*)selfmodule;
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)dos_headers + dos_headers->e_lfanew);
    IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt_headers);
    for (unsigned int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section_header++) {
        BYTE* section_addr = (BYTE*)selfmodule + section_header->VirtualAddress;
        SIZE_T section_size = section_header->Misc.VirtualSize ? section_header->Misc.VirtualSize : section_header->SizeOfRawData;
        DWORD old_prot;
        if (LI_FN(VirtualProtect).safe()(section_addr, section_size, PAGE_READWRITE, &old_prot)) { //
            for (SIZE_T j = 0; j < section_size; j++) {
                section_addr[j] = rand() % 256;
            }
            LI_FN(VirtualProtect).safe()(section_addr, section_size, old_prot, &old_prot);
        }
    }
}
constexpr size_t size_of_crc = 256; // size 256 bt
std::array<uint32_t, size_of_crc> crc_table;
void initialize_crc_table() { // first initialzation
    const uint32_t polynomial = 0xEDB88320;
    for (uint32_t i = 0; i < size_of_crc; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ (polynomial & (-(static_cast<int32_t>(crc & 1))));
        }
        crc_table[i] = crc;
    }
}
uint32_t crc32(const std::vector<uint8_t>& data) { // crc calculation function.
    uint32_t crc = 0xFFFFFFFF;
    for (auto byte : data) {
        uint8_t index = static_cast<uint8_t>(crc ^ byte);
        crc = (crc >> 8) ^ crc_table[index];
    }
    return ~crc;
}
std::vector<uint8_t> firstsection() { // get .text section, why .text because the valid executable's first section is .text, whatever.. it'll get it to calc the hash for comparison.
    HMODULE selfmodule = GetModuleHandle(NULL);
    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(selfmodule);
    auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<uint8_t*>(selfmodule) + dos_header->e_lfanew);
    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);
    std::vector<uint8_t> section_data(section_header->SizeOfRawData);
    std::memcpy(
        section_data.data(),
        reinterpret_cast<uint8_t*>(selfmodule) + section_header->PointerToRawData,
        section_header->SizeOfRawData
    );
    return section_data;
}
// PoC usage
void crc_check(std::atomic<bool>& loop) {
    HMODULE selfmodule = GetModuleHandle(NULL);
    auto orig_section = firstsection(); // getting first section
    uint32_t last_crc = crc32(orig_section); // calculating it
    while (loop) {
        try {
            auto curr_section = firstsection();
            uint32_t curr_crc = crc32(curr_section);
            if (curr_crc != last_crc) { // mismatched
                std::cerr << "[*BAD] CRC change detected!" << std::endl; // lets inform the user about change and mismatch on comparison, and address.
                for (size_t i = 0; i < orig_section.size(); ++i) {
                    if (orig_section[i] != curr_section[i]) {
                        uint8_t* modif_address = reinterpret_cast<uint8_t*>(selfmodule) +
                            IMAGE_FIRST_SECTION(reinterpret_cast<PIMAGE_NT_HEADERS>(
                                reinterpret_cast<uint8_t*>(selfmodule) + reinterpret_cast<PIMAGE_DOS_HEADER>(selfmodule)->e_lfanew))->PointerToRawData + i;
                        std::cout << "[*BAD] mismatch at address: 0x" << std::hex << reinterpret_cast<uintptr_t>(modif_address) // hacked address.
                            << " old value: 0x" << std::hex << static_cast<int>(orig_section[i])
                            << " new value: 0x" << std::hex << static_cast<int>(curr_section[i]) << std::endl;
                    }
                }
                last_crc = curr_crc;
                orig_section = curr_section;
            }
            else { // it matched. No hacked addresses, clean crc.
                std::cout << "[*GOOD] CRC is ok: 0x" << std::hex << curr_crc << std::endl; //  informing user that is CRC is ok.
            }
        }
        catch (const std::exception& e) {
            printf("something bad happened, exiting!");
            Sleep(5000);
            exit(0); 
        }
        std::this_thread::sleep_for(std::chrono::seconds(2)); // prevent high cpu usage with adding 2 second delay.
    }
}
