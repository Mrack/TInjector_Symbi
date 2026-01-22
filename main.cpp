#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include <sys/stat.h>
#include <cstring>
#include <algorithm>
#include <dirent.h>
#include "stub/stub.h"
#include <sstream>
#include "stub.h"


volatile sig_atomic_t keep_running = 1;

void signal_handler(int setting) {
    keep_running = 0;
}

#define TARGET_SYMBOL "_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring"

void print_banner() {
    printf("==================================================================\n");
    printf("                TInjector_Symbi                       \n");
    printf("        GitHub: https://github.com/Mrack     \n");
    printf("==================================================================\n");
}

void print_help(const char* proc_name) {
    print_banner();
    printf("Usage:\n");
    printf("  %s <package_name> <local_so_path>\n\n", proc_name);
    printf("Arguments:\n");
    printf("  <package_name>   Target app package (e.g., com.android.settings)\n");
    printf("  <local_so_path>  Path to the .so file (e.g., /data/local/tmp/libxxx.so)\n\n");
    printf("==================================================================\n\n");
}

struct MemoryMap {
    uintptr_t start;
    uintptr_t end;
    char perms[5];
    size_t offset;
    std::string pathname;
};

std::vector<MemoryMap> get_process_maps(pid_t pid) {
    std::vector<MemoryMap> maps;
    char path[64];
    sprintf(path, "/proc/%d/maps", pid);
    std::ifstream file(path);
    std::string line;
    while (std::getline(file, line)) {
        MemoryMap m;
        char p[5], dev[10], path_buf[512] = {0};
        unsigned long inode;
        if (sscanf(line.c_str(), "%lx-%lx %4s %lx %s %lu %s",
                   &m.start, &m.end, p, &m.offset, dev, &inode, path_buf) >= 6) {
            memcpy(m.perms, p, 5);
            m.pathname = path_buf;
            maps.push_back(m);
        }
    }
    return maps;
}

uintptr_t get_symbol_offset_from_elf(const std::string &elf_path, const char *symbol_name) {
    int fd = open(elf_path.c_str(), O_RDONLY);
    if (fd < 0) return 0;

    struct stat st;
    fstat(fd, &st);
    void *map_base = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (map_base == MAP_FAILED) return 0;

    auto *ehdr = (Elf64_Ehdr *) map_base;
    auto *shdr = (Elf64_Shdr *) ((uintptr_t) map_base + ehdr->e_shoff);
    auto *section_strtab = (char *) ((uintptr_t) map_base + shdr[ehdr->e_shstrndx].sh_offset);

    uintptr_t symbol_offset = 0;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_DYNSYM) {
            auto *syms = (Elf64_Sym *) ((uintptr_t) map_base + shdr[i].sh_offset);
            int count = shdr[i].sh_size / sizeof(Elf64_Sym);
            auto *strtab = (char *) ((uintptr_t) map_base + shdr[shdr[i].sh_link].sh_offset);

            for (int j = 0; j < count; j++) {
                if (strcmp(strtab + syms[j].st_name, symbol_name) == 0) {
                    symbol_offset = syms[j].st_value;
                    break;
                }
            }
        }
    }

    uintptr_t load_bias = 0;
    auto *phdr = (Elf64_Phdr *) ((uintptr_t) map_base + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            load_bias = phdr[i].p_vaddr;
            break;
        }
    }

    munmap(map_base, st.st_size);
    return symbol_offset - load_bias;
}

uintptr_t find_needle_in_remote_memory(int mem_fd, const MemoryMap &map, uintptr_t needle) {
    const size_t region_size = map.end - map.start;
    if (region_size < sizeof(uintptr_t)) return 0;

    std::vector<uint8_t> buffer(region_size);
    if (pread(mem_fd, buffer.data(), region_size, map.start) != static_cast<ssize_t>(region_size)) {
        return 0;
    }
    auto *start_ptr = buffer.data();
    auto *end_ptr = buffer.data() + region_size;
    auto *found = static_cast<uint8_t *>(memmem(start_ptr, region_size, &needle, sizeof(needle)));

    if (found) {
        return map.start + (found - start_ptr);
    }
    return 0;
}

struct ModuleCandidate {
    uintptr_t base;
    int total_ranges = 0;
    int executable_ranges = 0;

    int score() const {
        return (executable_ranges > 0) ? total_ranges : -total_ranges;
    }
};

uintptr_t get_module_base(int pid, const std::string &lib_name) {
    char path[64];
    sprintf(path, "/proc/%d/maps", pid);
    std::ifstream maps(path);
    std::string line;

    while (getline(maps, line)) {
        if (line.find(lib_name) == std::string::npos) {
            continue;
        }

        uintptr_t start, offset;
        char perms[5];
        if (sscanf(line.c_str(), "%lx-%*x %4s %lx", &start, perms, &offset) == 3) {
            if (offset == 0 && perms[3] != 's') {
                return start;
            }
        }
    }

    return 0;
}

uid_t get_uid_from_package(const char *package_name) {
    std::ifstream pkg_file("/data/system/packages.list");
    if (!pkg_file.is_open()) {
        perror("[-] Failed to open packages.list");
        return -1;
    }

    std::string line;
    while (std::getline(pkg_file, line)) {
        if (line.find(package_name) != std::string::npos) {
            std::stringstream ss(line);
            std::string pkg;
            uid_t uid;
            if (ss >> pkg >> uid) {
                if (pkg == package_name) {
                    return uid;
                }
            }
        }
    }
    return -1;
}

pid_t find_pid_by_name(const char *process_name) {
    DIR *dir = opendir("/proc");
    if (!dir) return -1;
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (!isdigit(entry->d_name[0])) continue;

        char cmdline_path[64];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", entry->d_name);

        std::ifstream cmdline_file(cmdline_path);
        std::string cmdline;
        if (std::getline(cmdline_file, cmdline)) {
            if (cmdline.find(process_name) != std::string::npos) {
                closedir(dir);
                return (pid_t) atoi(entry->d_name);
            }
        }
    }
    closedir(dir);
    return -1;
}

uintptr_t get_remote_symbol(pid_t pid, const std::string &lib_name, const char *symbol) {
    uintptr_t base = get_module_base(pid, lib_name);
    if (base == 0) return 0;

    auto maps = get_process_maps(pid);
    std::string local_path;
    for (auto &m: maps) {
        if (m.pathname.find(lib_name) != std::string::npos) {
            local_path = m.pathname;
            break;
        }
    }

    uintptr_t offset = get_symbol_offset_from_elf(local_path, symbol);
    return (offset != 0) ? (base + offset) : 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_help(argv[0]);
        return 0;
    }
    print_banner();


    signal(SIGINT, signal_handler);

    pid_t target_pid = find_pid_by_name("zygote64");
    const char *package_name = argv[1];
    pid_t target_uid = get_uid_from_package(package_name);
    char *so_path = argv[2];
    if (target_uid == -1) {
        printf("[-] Failed to find package %s.\n", argv[1]);
        return 1;
    }

    printf("[*] Target Zygote PID: %d UID: %d SO: %s\n", target_pid, target_uid, so_path);

    kill(target_pid, SIGSTOP);

    auto maps = get_process_maps(target_pid);
    uintptr_t libandroid_runtime_base = 0;
    std::string libandroid_runtime_path;
    std::string libstagefright_path;
    uintptr_t shellcode_base;
    std::vector<MemoryMap> heap_candidates;


    int mem_fd = open(("/proc/" + std::to_string(target_pid) + "/mem").c_str(), O_RDWR);
    if (mem_fd < 0) {
        perror("[-] Failed to open /proc/pid/mem");
        kill(target_pid, SIGCONT);
        return 1;
    }


    for (const auto &m: maps) {
        if (m.pathname.find("libstagefright.so") != std::string::npos &&
            (m.perms[2] == 'x')) {
            shellcode_base = m.end - getpagesize();
            libstagefright_path = m.pathname;
        }
        if (m.pathname.find("libandroid_runtime.so") != std::string::npos) {
            libandroid_runtime_path = m.pathname;
        }
        if (
                (m.pathname.find("boot.art") != std::string::npos ||
                 m.pathname.find("boot-framework.art") != std::string::npos ||
                 m.pathname.find("dalvik-LinearAlloc") != std::string::npos)
                &&
                (m.perms[0] == 'r' && m.perms[1] == 'w')) {
            heap_candidates.push_back(m);
        }
    }

    libandroid_runtime_base = get_module_base(target_pid, libandroid_runtime_path);

    if (libandroid_runtime_base == 0) {
        fprintf(stderr, "[-] Could not find libandroid_runtime.so in target\n");

        kill(target_pid, SIGCONT);
        return 1;
    }
    uintptr_t symbol_offset = get_symbol_offset_from_elf(libandroid_runtime_path, TARGET_SYMBOL);
    if (symbol_offset == 0) {
        fprintf(stderr, "[-] Could not find symbol in ELF file\n");

        kill(target_pid, SIGCONT);
        return 1;
    }

    uintptr_t set_argv0_address = libandroid_runtime_base + symbol_offset;
    printf("[+] Found setArgv0 needle: %s 0x%lx 0x%lx\n", libandroid_runtime_path.c_str(), symbol_offset,
           set_argv0_address);


    char remote_pattern[] = "/mmmmmrack87654321";
    auto pp = (uintptr_t) memmem(stub_binary, stub_binary_size, remote_pattern, sizeof remote_pattern);
    if (pp) {

        uintptr_t art_method_slot = 0;

//        uintptr_t addr_stub = find_needle_in_remote_memory(mem_fd, MemoryMap{
//                .start = shellcode_base,
//                .end = shellcode_base + getpagesize(),
//        }, *(uintptr_t *) remote_pattern);
//        if (addr_stub) {
//            TStub temp_stub;
//            if (pread(mem_fd, &temp_stub, sizeof(TStub), addr_stub) == sizeof(TStub)) {
//                art_method_slot = temp_stub.slot_addr;
//            }
//        } else
        {
            printf("[*] Searching for needle in %zu heap regions...\n", heap_candidates.size());
            for (const auto &heap: heap_candidates) {
                art_method_slot = find_needle_in_remote_memory(mem_fd, heap, set_argv0_address);
                if (art_method_slot) {
                    printf("[!] SUCCESS! Found art_method_slot at: 0x%lx\n", art_method_slot);
                    printf("[*] This slot belongs to map: %s (0x%lx - 0x%lx)\n",
                           heap.pathname.empty() ? "[anonymous]" : heap.pathname.c_str(), heap.start, heap.end);
                    break;
                }
            }


            if (!art_method_slot) {
                printf("[-] Failed to find the needle in any heap region.\n");
                close(mem_fd);
                kill(target_pid, SIGCONT);
                return 1;
            }

        }

        std::string target_dir = "/data/data/" + std::string(package_name) + "/cache";
        std::string remote_so_path = target_dir + "/" + "lib" + std::to_string(target_uid) + ".so";
        printf("[*] Preparing SO for SELinux compliance...\n");

        std::string cp_cmd = "cp " + std::string(so_path) + " " + remote_so_path;
        system(cp_cmd.c_str());

        std::string chown_cmd =
                "chown " + std::to_string(target_uid) + ":" + std::to_string(target_uid) + " " + remote_so_path;
        system(chown_cmd.c_str());

        so_path = remote_so_path.data();

        uintptr_t original_ptr;
        pread(mem_fd, &original_ptr, sizeof(uintptr_t), art_method_slot);

        printf("[*] Verification: Slot 0x%lx contains 0x%lx shellcode base  0x%lx\n", art_method_slot, original_ptr,
               shellcode_base);

        std::vector<uint8_t> original_shellcode_area(stub_binary_size);
        pread(mem_fd, original_shellcode_area.data(), stub_binary_size, shellcode_base);


        uintptr_t offset = pp - (uintptr_t) stub_binary;
        auto *pStub = (TStub *) (stub_binary + offset);

        pStub->uid = target_uid;
        strcpy(pStub->so_path, so_path);

        uintptr_t addr_log = get_remote_symbol(target_pid, "liblog.so", "__android_log_print");
        pStub->log_print = reinterpret_cast<int (*)(int, const char *, const char *, ...)>(addr_log);

        uintptr_t addr_getuid = get_remote_symbol(target_pid, "libc.so", "getuid");
        pStub->getuid = reinterpret_cast<uid_t (*)()>(addr_getuid);

        uintptr_t addr_dlopen = get_remote_symbol(target_pid, "libdl.so", "dlopen");
        pStub->dlopen = reinterpret_cast<void *(*)(const char *, int)>(addr_dlopen);

        pStub->original_set_argv0 = reinterpret_cast<int (*)(JNIEnv *, jobject, jstring)>(set_argv0_address);
        pStub->slot_addr = art_method_slot;

        ssize_t written_code = pwrite(mem_fd, stub_binary, stub_binary_size, shellcode_base);
        if (written_code != stub_binary_size) {
            printf("[-] Failed to write shellcode to shellcode_base");
            close(mem_fd);
            kill(target_pid, SIGCONT);
            return 1;
        }

        uintptr_t new_ptr = shellcode_base;
        ssize_t written_ptr = pwrite(mem_fd, &new_ptr, sizeof(new_ptr), art_method_slot);

        if (written_ptr != sizeof(new_ptr)) {
            printf("[-] Failed to write now points to art_method_slot");
            close(mem_fd);
            kill(target_pid, SIGCONT);
            return 1;
        }

        printf("[!] HOOK SUCCESS! art_method_slot now points to Shellcode.\n");


        kill(target_pid, SIGCONT);

        system(std::string("am force-stop ").append(package_name).c_str());
        system(std::string("am start -D $(cmd package resolve-activity --brief '").append(package_name).append(
                "'| tail -n 1)").c_str());


        printf("[*] Press Ctrl+C to restore and exit.\n");

        while (keep_running) {
            sleep(1);
        }

        printf("\n[*] Restoring Zygote memory...\n");
        kill(target_pid, SIGSTOP);

        pwrite(mem_fd, &original_ptr, sizeof(original_ptr), art_method_slot);
        pwrite(mem_fd, original_shellcode_area.data(), stub_binary_size, shellcode_base);

        kill(target_pid, SIGCONT);

        close(mem_fd);
        printf("[+] Restore complete. Goodbye!\n");

    } else {
        printf("[!] Payload Error\n");
        close(mem_fd);
    }


    return 0;
}
