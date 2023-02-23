#include <iostream>

void* alloc_code(size_t size);

#ifdef _WIN32
#include <Windows.h>

void* alloc_code(size_t size)
{
    return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}
#endif

size_t (*shellcode)() = nullptr;

extern size_t shellcode_win64_len;
extern unsigned char shellcode_win64[];

void test()
{
    std::cout << "Fake original entrypoint was called!" << std::endl;
}

void call_shellcode()
{
    size_t shellcode_len = 0;
    unsigned char* shellcode_source = nullptr;
    #ifdef _WIN64
    shellcode_len = shellcode_win64_len;
    shellcode_source = shellcode_win64;
    #else
    #   error "Unsupported platform"
    #endif

    shellcode = reinterpret_cast<decltype(shellcode)>(alloc_code(shellcode_len));
    std::memcpy(shellcode, shellcode_source, shellcode_len);

    std::cout << "Executing shellcode @ " << std::hex << reinterpret_cast<ptrdiff_t>(shellcode) << std::endl;
    auto result = shellcode();
    std::cout << "Shellcode returned " << std::hex << result << std::endl;
    
    std::cout << "Press enter to continue" << std::endl;
    std::cin.get();
}

int main(int argc, const char** argv)
{
    auto res = LoadLibraryA("patched.dll");
    if (res == nullptr)
    {
        std::cout << "Failed to load dll" << std::endl;
        auto err = GetLastError();
        char errorBuffer[256];
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
            errorBuffer, (sizeof(errorBuffer)), NULL);
        std::cout << "Reason: '" << errorBuffer << "'" << std::endl;
    }
    std::cout << "Done" << std::endl;
    std::cin.get();
    return 0;
}