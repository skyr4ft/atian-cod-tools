#include <includes.hpp>
#include <Windows.h>
#include <tools/fastfile/handlers/handler_game_bo7.hpp>

/*
 * Raw dumper for the weapon related assets of Black Ops 7.
 *
 * The structures of these assets are not mapped yet, so this worker writes the raw asset
 * structure, the memory referenced by its pointers and every hash it can resolve. The output
 * can then be decoded offline.
 *
 * Output: <output>/bo7/source/weaponraw/<type>/<name>.bin      raw asset structure
 *         <output>/bo7/source/weaponraw/<type>/<name>.ptr.bin  concatenated pointed blocks
 *         <output>/bo7/source/weaponraw/<type>/<name>.json     pointers, strings and hashes
 */
namespace {
    using namespace fastfile::handlers::bo7;

    constexpr size_t MAX_POINTED_DUMP = 0x1000;
    constexpr size_t MAX_STRING_LEN = 0x200;
    constexpr uintptr_t MIN_USER_PTR = 0x10000;
    constexpr uintptr_t MAX_USER_PTR = 0x7FFFFFFFFFFF;

    enum PointerKind {
        PK_NONE = 0,
        PK_DATA,
        PK_IMAGE,
    };

    PointerKind GetPointerKind(const void* ptr, size_t* readable) {
        *readable = 0;
        uintptr_t loc{ (uintptr_t)ptr };
        if (loc < MIN_USER_PTR || loc > MAX_USER_PTR) {
            return PK_NONE;
        }
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(ptr, &mbi, sizeof(mbi))) {
            return PK_NONE;
        }
        if (mbi.State != MEM_COMMIT) {
            return PK_NONE;
        }
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) {
            return PK_NONE;
        }
        constexpr DWORD readableMask{ PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                                      PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY };
        if (!(mbi.Protect & readableMask)) {
            return PK_NONE;
        }
        uintptr_t end{ (uintptr_t)mbi.BaseAddress + mbi.RegionSize };
        *readable = (size_t)(end - loc);
        return mbi.Type == MEM_IMAGE ? PK_IMAGE : PK_DATA;
    }

    std::string JsonEscape(const char* str) {
        std::string out{};
        for (const char* c{ str }; *c; c++) {
            unsigned char v{ (unsigned char)*c };
            if (v == '"' || v == '\\') {
                out += '\\';
                out += (char)v;
            } else if (v < 0x20 || v >= 0x7F) {
                out += std::format("\\u{:04x}", (int)v);
            } else {
                out += (char)v;
            }
        }
        return out;
    }

    std::string SafeFileName(const char* str) {
        std::string out{};
        for (const char* c{ str }; *c; c++) {
            char v{ *c };
            if (v == '/' || v == '\\' || v == ':' || v == '*' || v == '?' || v == '"' || v == '<' || v == '>' ||
                v == '|') {
                out += '_';
            } else {
                out += v;
            }
        }
        return out;
    }

    // returns the string if ptr points to a printable null terminated string
    const char* ReadString(const void* ptr, size_t readable) {
        const char* str{ (const char*)ptr };
        size_t max{ (std::min<size_t>)(readable, MAX_STRING_LEN) };
        size_t i{};
        for (; i < max; i++) {
            unsigned char c{ (unsigned char)str[i] };
            if (!c) {
                break;
            }
            if (c < 0x20 || c >= 0x7F) {
                return nullptr;
            }
        }
        if (i < 3 || i == max) {
            return nullptr;
        }
        return str;
    }

    // write the resolved hashes found in a memory block
    void WriteHashes(std::ostream& os, const byte* data, size_t len) {
        bool first{ true };
        os << "[";
        for (size_t off{}; off + sizeof(uint64_t) <= len; off += sizeof(uint64_t)) {
            uint64_t val{ *(const uint64_t*)(data + off) };
            if (!val) {
                continue;
            }
            const char* name{ hashutils::ExtractPtr(val) };
            if (!name) {
                continue;
            }
            if (!first) {
                os << ",";
            }
            first = false;
            os << "{\"off\":\"0x" << std::hex << off << std::dec << "\",\"name\":\"" << JsonEscape(name) << "\"}";
        }
        os << "]";
    }

    // write the pointers found in a pointed block, with the name of the asset they point to
    void WriteSubPointers(std::ostream& os, const byte* data, size_t len) {
        bool first{ true };
        os << "[";
        for (size_t off{}; off + sizeof(uint64_t) <= len; off += sizeof(uint64_t)) {
            const void* sub{ *(const void* const*)(data + off) };
            size_t readable{};
            if (GetPointerKind(sub, &readable) != PK_DATA || readable < sizeof(uint64_t)) {
                continue;
            }
            uint64_t subHash{ *(const uint64_t*)sub };
            const char* subName{ subHash ? hashutils::ExtractPtr(subHash) : nullptr };
            const char* subStr{ ReadString(sub, readable) };
            if (!first) {
                os << ",";
            }
            first = false;
            os << "{\"off\":\"0x" << std::hex << off << std::dec << "\"";
            if (subName) {
                os << ",\"asset\":\"" << JsonEscape(subName) << "\"";
            } else if (subHash) {
                os << ",\"first\":\"0x" << std::hex << subHash << std::dec << "\"";
            }
            if (subStr) {
                os << ",\"str\":\"" << JsonEscape(subStr) << "\"";
            }
            os << "}";
        }
        os << "]";
    }

    class ImplWorker : public Worker {
        SatHashAssetType type;
        const char* typeName;

      public:
        ImplWorker(size_t assetSize, SatHashAssetType type, const char* typeName)
            : Worker(assetSize), type(type), typeName(typeName) {}

        void Unlink(fastfile::FastFileOption& opt, fastfile::FastFileContext& ctx, void* ptr) override {
            const byte* asset{ (const byte*)ptr };
            uint64_t hash{ GetXAssetName(type, ptr) };
            const char* name{ hashutils::ExtractPtr(hash) };
            std::string fileName{ name ? SafeFileName(name) : std::format("hash_{:x}", hash) };

            std::filesystem::path outDir{ opt.m_output / gamePath / "source" / "weaponraw" / typeName };
            std::filesystem::create_directories(outDir);

            std::filesystem::path binFile{ outDir / (fileName + ".bin") };
            std::filesystem::path ptrFile{ outDir / (fileName + ".ptr.bin") };
            std::filesystem::path jsonFile{ outDir / (fileName + ".json") };

            if (!utils::WriteFile(binFile, asset, assetSize)) {
                LOG_ERROR("Error when dumping {}", binFile.string());
                return;
            }

            std::vector<byte> pointed{};
            std::ostringstream ptrs{};
            bool firstPtr{ true };

            ptrs << "[";
            for (size_t off{}; off + sizeof(uint64_t) <= assetSize; off += sizeof(uint64_t)) {
                const void* target{ *(const void* const*)(asset + off) };
                size_t readable{};
                PointerKind kind{ GetPointerKind(target, &readable) };
                if (kind == PK_NONE) {
                    continue;
                }

                if (!firstPtr) {
                    ptrs << ",";
                }
                firstPtr = false;

                ptrs << "\n  {\"off\":\"0x" << std::hex << off << "\",\"target\":\"0x" << (uintptr_t)target
                     << std::dec << "\"";

                if (kind == PK_IMAGE) {
                    // pointer into the game executable (vtable, function, constant data)
                    ptrs << ",\"image\":true}";
                    continue;
                }

                size_t len{ (std::min<size_t>)(readable, MAX_POINTED_DUMP) };
                const byte* data{ (const byte*)target };
                const char* str{ ReadString(target, readable) };

                ptrs << ",\"blob_off\":" << pointed.size() << ",\"blob_len\":" << len;
                if (str) {
                    ptrs << ",\"str\":\"" << JsonEscape(str) << "\"";
                }
                ptrs << ",\"hashes\":";
                WriteHashes(ptrs, data, len);
                ptrs << ",\"sub\":";
                WriteSubPointers(ptrs, data, len);
                ptrs << "}";

                pointed.insert(pointed.end(), data, data + len);
            }
            ptrs << "\n]";

            if (!pointed.empty() && !utils::WriteFile(ptrFile, pointed.data(), pointed.size())) {
                LOG_ERROR("Error when dumping {}", ptrFile.string());
            }

            std::ofstream json{ jsonFile, std::ios::out | std::ios::binary };
            if (!json) {
                LOG_ERROR("Can't open {}", jsonFile.string());
                return;
            }
            json << "{\n\"type\":\"" << typeName << "\",\n\"name\":\"" << (name ? JsonEscape(name) : "")
                 << "\",\n\"hash\":\"0x" << std::hex << hash << std::dec << "\",\n\"size\":\"0x" << std::hex
                 << assetSize << std::dec << "\",\n\"hashes\":";
            WriteHashes(json, asset, assetSize);
            json << ",\n\"pointers\":" << ptrs.str() << "\n}\n";
            json.close();

            LOG_OPT_INFO("Dump {} {} (0x{:x})", typeName, binFile.string(), assetSize);
        }
    };

    // sizes from the pool info of the game (code/bo7_poolinfo.csv), they must match the exe
    utils::MapAdder<ImplWorker, SatHashAssetType, Worker> implWeapon{
        GetWorkers(), SatHashAssetType::SATH_ASSET_WEAPON, (size_t)0x568, SatHashAssetType::SATH_ASSET_WEAPON,
        "weapon"
    };
    utils::MapAdder<ImplWorker, SatHashAssetType, Worker> implAttachment{
        GetWorkers(), SatHashAssetType::SATH_ASSET_ATTACHMENT, (size_t)0xe10, SatHashAssetType::SATH_ASSET_ATTACHMENT,
        "attachment"
    };
    utils::MapAdder<ImplWorker, SatHashAssetType, Worker> implWeaponTunables{
        GetWorkers(), SatHashAssetType::SATH_ASSET_WEAPONTUNABLES, (size_t)0x5e68,
        SatHashAssetType::SATH_ASSET_WEAPONTUNABLES, "weapontunables"
    };
    utils::MapAdder<ImplWorker, SatHashAssetType, Worker> implWeaponBlueprint{
        GetWorkers(), SatHashAssetType::SATH_ASSET_WEAPONBLUEPRINT, (size_t)0x200,
        SatHashAssetType::SATH_ASSET_WEAPONBLUEPRINT, "weaponblueprint"
    };
    utils::MapAdder<ImplWorker, SatHashAssetType, Worker> implAttachmentBlueprint{
        GetWorkers(), SatHashAssetType::SATH_ASSET_ATTACHMENTBLUEPRINT, (size_t)0x1a0,
        SatHashAssetType::SATH_ASSET_ATTACHMENTBLUEPRINT, "attachmentblueprint"
    };
} // namespace
