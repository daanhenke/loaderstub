#include <string>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <vector>

#include <Windows.h>

typedef struct
{
    IMAGE_SECTION_HEADER Header;
    char* Buffer;
} SectionInfo;

typedef struct
{
    IMAGE_DOS_HEADER Dos;
    IMAGE_NT_HEADERS64 Nt;
    char* HeaderBuffer;
    size_t HeaderBufferSize;
    std::vector<SectionInfo> Sections;
} SplicedPE;

void ReadAt(size_t offset, char* out, size_t size, std::ifstream& stream)
{
    stream.seekg(offset, std::ios::beg);
    stream.read(reinterpret_cast<char*>(out), size);
}

template <typename T>
void ReadAt(size_t offset, T* out, std::ifstream& stream)
{
    ReadAt(offset, reinterpret_cast<char*>(out), sizeof(T), stream);
}

extern size_t shellcode_win64_len;
extern unsigned char shellcode_win64[];
bool AddStubToPE(std::string sourcePath, std::string destPath, std::string loadedDll)
{
    if (! std::filesystem::exists(sourcePath))
    {
        std::cout << "source file not found" << std::endl;
        return false;
    }

    std::ifstream sourceStream(sourcePath, std::fstream::binary);
    SplicedPE pe;
    
    ReadAt(0, &pe.Dos, sourceStream);
    if (pe.Dos.e_magic != 0x5A4D)
    {
        std::cout << "dos header corrupt" << std::endl;
        sourceStream.close();
        return false;
    }

    ReadAt(pe.Dos.e_lfanew, &pe.Nt, sourceStream);
    if (pe.Nt.Signature != 0x4550)
    {
        std::cout << "nt header corrupt" << std::endl;
        sourceStream.close();
        return false;
    }

    pe.HeaderBufferSize = pe.Dos.e_lfanew + sizeof(pe.Nt.Signature) + sizeof(pe.Nt.FileHeader) + pe.Nt.FileHeader.SizeOfOptionalHeader;
    pe.HeaderBuffer = new char[pe.HeaderBufferSize];
    std::cout << "DOS + NT headers size: " << std::hex << pe.HeaderBufferSize << std::endl;

    ReadAt(0, pe.HeaderBuffer, pe.HeaderBufferSize, sourceStream);

    SectionInfo stubSection;
    ptrdiff_t stubSectionOffset = 0;
    ptrdiff_t stubSectionRva = 0;
    for (auto i = 0; i < pe.Nt.FileHeader.NumberOfSections; i++)
    {
        SectionInfo info;
        info.Buffer = nullptr;
        ReadAt(pe.HeaderBufferSize + (i * sizeof(IMAGE_SECTION_HEADER)), &info.Header, sourceStream);

        char* sectionName = reinterpret_cast<char*>(info.Header.Name);
        if (info.Header.SizeOfRawData == 0)
        {
            std::cout << "Skipping section '" << sectionName << "'" << std::endl;
            continue;
        }

        stubSectionOffset = info.Header.PointerToRawData + info.Header.SizeOfRawData;
        stubSectionRva = info.Header.VirtualAddress + info.Header.Misc.VirtualSize;

        std::cout << "Reading section '" << sectionName << "\tF(" << std::hex 
            << info.Header.PointerToRawData << " - " << info.Header.PointerToRawData + info.Header.SizeOfRawData << ")\tVA("
            << info.Header.VirtualAddress << " - " << info.Header.VirtualAddress + info.Header.Misc.VirtualSize << ")" << std::endl;

        info.Buffer = new char[info.Header.SizeOfRawData];
        ReadAt(info.Header.PointerToRawData, info.Buffer, info.Header.SizeOfRawData, sourceStream);
        pe.Sections.emplace_back(info);

        if (std::string(sectionName) == ".text")
        {
            std::cout << " - also using it as the base of our stub section" << std::endl;
            stubSection = info;
        }
    }

    sourceStream.close();

    auto loadedDllPathLengthWithoutZeroTerminator = loadedDll.size();
    auto stubLength = shellcode_win64_len + loadedDllPathLengthWithoutZeroTerminator;
    stubSection.Buffer = new char[stubLength];
    std::memcpy(stubSection.Buffer, shellcode_win64, shellcode_win64_len);
    std::memcpy(stubSection.Buffer + shellcode_win64_len - 1, loadedDll.c_str(), loadedDllPathLengthWithoutZeroTerminator + 1);
    std::memcpy(stubSection.Buffer + shellcode_win64_len - 5, &pe.Nt.OptionalHeader.AddressOfEntryPoint, sizeof(uint32_t));

    stubSectionRva &= ~0xFFF;
    stubSectionRva += 0x1000;
    std::memcpy(&stubSection.Header.Name, ".stub\0\0\0", 8);
    // stubSection.Header.Characteristics = \
    //     IMAGE_SCN_MEM_READ
    //     | IMAGE_SCN_MEM_EXECUTE
    //     | IMAGE_SCN_CNT_CODE;
    stubSection.Header.NumberOfLinenumbers = 0;
    stubSection.Header.NumberOfRelocations = 0;
    stubSection.Header.PointerToLinenumbers = 0;
    stubSection.Header.PointerToRelocations = 0;
    stubSection.Header.SizeOfRawData = stubLength;
    stubSection.Header.Misc.VirtualSize = stubLength;
    stubSection.Header.PointerToRawData = stubSectionOffset;
    stubSection.Header.VirtualAddress = stubSectionRva;
    pe.Sections.emplace_back(stubSection);

    pe.Nt.OptionalHeader.AddressOfEntryPoint = stubSection.Header.VirtualAddress;
    pe.Nt.OptionalHeader.SizeOfHeaders += pe.Nt.OptionalHeader.FileAlignment;
    pe.Nt.FileHeader.NumberOfSections++;
    pe.Nt.OptionalHeader.SizeOfImage += pe.Nt.OptionalHeader.SectionAlignment;

    std::cout << "Created stub section '" << stubSection.Header.Name << "'\tF(" << std::hex 
        << stubSectionOffset << " - " << stubSectionOffset + stubSection.Header.SizeOfRawData << ")\tVA("
        << stubSectionRva << " - " << stubSectionRva + stubSection.Header.Misc.VirtualSize << ")" << std::endl;

    std::ofstream destStream(destPath, std::ios::binary);
    destStream.clear();

    auto i = 0;
    for (auto& section : pe.Sections)
    {
        destStream.seekp(section.Header.PointerToRawData, std::ios::beg);
        destStream.write(section.Buffer, section.Header.SizeOfRawData);
        
        destStream.seekp(pe.HeaderBufferSize + (i++ * sizeof(IMAGE_SECTION_HEADER)), std::ios::beg);
        destStream.write(reinterpret_cast<char*>(&section.Header), sizeof(IMAGE_SECTION_HEADER));
    }


    destStream.seekp(0, std::ios::beg);
    destStream.write(pe.HeaderBuffer, pe.HeaderBufferSize);

    destStream.seekp(pe.Dos.e_lfanew + sizeof(pe.Nt.Signature) + sizeof(pe.Nt.FileHeader), std::ios::beg);
    destStream.write(reinterpret_cast<char*>(&pe.Nt.OptionalHeader), pe.Nt.FileHeader.SizeOfOptionalHeader);

    destStream.seekp(pe.Dos.e_lfanew + sizeof(pe.Nt.Signature), std::ios::beg);
    destStream.write(reinterpret_cast<char*>(&pe.Nt.FileHeader), sizeof(pe.Nt.FileHeader));

    destStream.flush();
    destStream.close();
    return true;
}

int main(int argc, const char** argv)
{
    return AddStubToPE("target.dll", "patched.dll", "modloader.dll") == true;
}