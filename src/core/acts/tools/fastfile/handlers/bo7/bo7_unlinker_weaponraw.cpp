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
 *         <output>/bo7/source/weaponraw/xanim_index.jsonl      xanim headers, one per line
 *         <output>/bo7/source/weaponraw/<type>/<name>.ptr.bin  concatenated pointed blocks
 *         <output>/bo7/source/weaponraw/<type>/<name>.json     pointers, strings and hashes
 */
namespace {
    using namespace fastfile::handlers::bo7;

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

    struct DumpConfig {
        size_t window;      // bytes saved behind each top-level pointer
        size_t deepMaxOff;  // top-level pointers at or below this struct offset use deepWindow
        size_t deepWindow;  // bytes saved behind those pointers
        int nestedDepth;    // how many extra pointer levels to follow from the saved blocks
        size_t nestedWindow;
        size_t nestedScan;  // how many bytes of a block are scanned for further pointers
        bool aggregate;     // struct only, one line per asset in a shared index file
    };

    struct BlobWriter {
        std::vector<byte> data{};
        std::unordered_map<uintptr_t, std::pair<size_t, size_t>> seen{};

        // returns (offset, len) in the blob, reusing a previous copy of the same address
        std::pair<size_t, size_t> Add(const byte* ptr, size_t len, bool* reused) {
            std::unordered_map<uintptr_t, std::pair<size_t, size_t>>::iterator it{ seen.find((uintptr_t)ptr) };
            if (it != seen.end() && it->second.second >= len) {
                *reused = true;
                return it->second;
            }
            *reused = false;
            std::pair<size_t, size_t> pos{ data.size(), len };
            data.insert(data.end(), ptr, ptr + len);
            seen[(uintptr_t)ptr] = pos;
            return pos;
        }
    };

    class ImplWorker : public Worker {
        SatHashAssetType type;
        const char* typeName;
        DumpConfig cfg;
        std::ofstream aggregateOut{};

        void WriteBlockInfo(std::ostream& os, const byte* data, size_t len, size_t readable) {
            const char* str{ ReadString(data, readable) };
            if (str) {
                os << ",\"str\":\"" << JsonEscape(str) << "\"";
            }
            os << ",\"hashes\":";
            WriteHashes(os, data, len);
            os << ",\"sub\":";
            WriteSubPointers(os, data, len);
        }

        void DumpNested(std::ostream& os, BlobWriter& blob, std::unordered_set<uintptr_t>& visited,
                        const byte* data, size_t len, uintptr_t parent, int depth, bool& first) {
            if (depth <= 0) {
                return;
            }
            size_t scan{ (std::min<size_t>)(len, cfg.nestedScan) };
            for (size_t off{}; off + sizeof(uint64_t) <= scan; off += sizeof(uint64_t)) {
                const void* target{ *(const void* const*)(data + off) };
                size_t readable{};
                if (GetPointerKind(target, &readable) != PK_DATA) {
                    continue;
                }
                if (visited.contains((uintptr_t)target)) {
                    continue;
                }
                visited.insert((uintptr_t)target);
                size_t sublen{ (std::min<size_t>)(readable, cfg.nestedWindow) };
                bool reused{};
                std::pair<size_t, size_t> pos{ blob.Add((const byte*)target, sublen, &reused) };
                if (!first) {
                    os << ",";
                }
                first = false;
                os << "\n  {\"parent\":\"0x" << std::hex << parent << "\",\"off\":\"0x" << off
                   << "\",\"target\":\"0x" << (uintptr_t)target << std::dec << "\",\"blob_off\":" << pos.first
                   << ",\"blob_len\":" << pos.second;
                WriteBlockInfo(os, (const byte*)target, sublen, readable);
                os << "}";
                DumpNested(os, blob, visited, (const byte*)target, sublen, (uintptr_t)target, depth - 1, first);
            }
        }

        void UnlinkAggregate(fastfile::FastFileOption& opt, const byte* asset, uint64_t hash, const char* name) {
            if (!aggregateOut.is_open()) {
                std::filesystem::path outDir{ opt.m_output / gamePath / "source" / "weaponraw" };
                std::filesystem::create_directories(outDir);
                aggregateOut.open(outDir / (std::string{ typeName } + "_index.jsonl"),
                                  std::ios::out | std::ios::binary | std::ios::app);
            }
            if (!aggregateOut) {
                return;
            }
            aggregateOut << "{\"name\":\"" << (name ? JsonEscape(name) : "") << "\",\"hash\":\"0x" << std::hex << hash
                         << "\",\"data\":\"";
            for (size_t i{}; i < assetSize; i++) {
                aggregateOut << std::format("{:02x}", (int)asset[i]);
            }
            aggregateOut << std::dec << "\"";
            if (cfg.window) {
                // pointed blocks, so links to other assets can be followed
                aggregateOut << ",\"ptrs\":[";
                bool first{ true };
                for (size_t off{}; off + sizeof(uint64_t) <= assetSize; off += sizeof(uint64_t)) {
                    const void* target{ *(const void* const*)(asset + off) };
                    size_t readable{};
                    if (GetPointerKind(target, &readable) != PK_DATA) {
                        continue;
                    }
                    size_t len{ (std::min<size_t>)(readable, cfg.window) };
                    const byte* data{ (const byte*)target };
                    if (!first) {
                        aggregateOut << ",";
                    }
                    first = false;
                    aggregateOut << "{\"off\":\"0x" << std::hex << off << std::dec << "\",\"data\":\"";
                    for (size_t i{}; i < len; i++) {
                        aggregateOut << std::format("{:02x}", (int)data[i]);
                    }
                    aggregateOut << "\",\"hashes\":";
                    WriteHashes(aggregateOut, data, len);
                    aggregateOut << "}";
                }
                aggregateOut << "]";
            }
            aggregateOut << "}\n";
        }

      public:
        ImplWorker(size_t assetSize, SatHashAssetType type, const char* typeName, DumpConfig cfg)
            : Worker(assetSize), type(type), typeName(typeName), cfg(cfg) {}

        void Unlink(fastfile::FastFileOption& opt, fastfile::FastFileContext& ctx, void* ptr) override {
            const byte* asset{ (const byte*)ptr };
            uint64_t hash{ GetXAssetName(type, ptr) };
            const char* name{ hashutils::ExtractPtr(hash) };

            if (cfg.aggregate) {
                UnlinkAggregate(opt, asset, hash, name);
                return;
            }

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

            BlobWriter blob{};
            std::unordered_set<uintptr_t> visited{};
            visited.insert((uintptr_t)asset);
            std::ostringstream ptrs{};
            std::ostringstream nested{};
            bool firstPtr{ true };
            bool firstNested{ true };

            ptrs << "[";
            nested << "[";
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

                size_t window{ off <= cfg.deepMaxOff ? cfg.deepWindow : cfg.window };
                size_t len{ (std::min<size_t>)(readable, window) };
                const byte* data{ (const byte*)target };
                bool reused{};
                std::pair<size_t, size_t> pos{ blob.Add(data, len, &reused) };
                bool firstVisit{ !visited.contains((uintptr_t)target) };
                visited.insert((uintptr_t)target);

                ptrs << ",\"blob_off\":" << pos.first << ",\"blob_len\":" << pos.second;
                WriteBlockInfo(ptrs, data, len, readable);
                ptrs << "}";

                if (firstVisit) {
                    DumpNested(nested, blob, visited, data, len, (uintptr_t)target, cfg.nestedDepth, firstNested);
                }
            }
            ptrs << "\n]";
            nested << "\n]";

            if (!blob.data.empty() && !utils::WriteFile(ptrFile, blob.data.data(), blob.data.size())) {
                LOG_ERROR("Error when dumping {}", ptrFile.string());
            }

            std::ofstream json{ jsonFile, std::ios::out | std::ios::binary };
            if (!json) {
                LOG_ERROR("Can't open {}", jsonFile.string());
                return;
            }
            // the asset's own address and fastfile, so pointers from other assets (a weapon to its
            // tunables, a Pack-a-Punch attachment to its tuning, a weapon to its anim package) can be matched
            json << "{\n\"type\":\"" << typeName << "\",\n\"name\":\"" << (name ? JsonEscape(name) : "")
                 << "\",\n\"hash\":\"0x" << std::hex << hash << std::dec << "\",\n\"addr\":\"0x" << std::hex
                 << (uintptr_t)asset << std::dec << "\",\n\"ff\":\"" << JsonEscape(ctx.ffname ? ctx.ffname : "")
                 << "\",\n\"size\":\"0x" << std::hex << assetSize << std::dec << "\",\n\"hashes\":";
            WriteHashes(json, asset, assetSize);
            json << ",\n\"pointers\":" << ptrs.str() << ",\n\"nested\":" << nested.str() << "\n}\n";
            json.close();

            LOG_OPT_INFO("Dump {} {} (0x{:x})", typeName, binFile.string(), assetSize);
        }
    };

    // window, deepMaxOff, deepWindow, nestedDepth, nestedWindow, nestedScan, aggregate
    constexpr DumpConfig CFG_ATTACHMENT{ 0x1000, 0, 0x1000, 0, 0, 0, false };
    constexpr DumpConfig CFG_WEAPON{ 0x1000, 0x60, 0x8000, 0, 0, 0, false }; // no nesting: the deep dump was too slow
    constexpr DumpConfig CFG_TUNABLES{ 0x1000, 0, 0x1000, 1, 0x400, 0x1000, false };
    constexpr DumpConfig CFG_BLUEPRINT{ 0x1000, 0, 0x1000, 0, 0, 0, false };
    constexpr DumpConfig CFG_ANIMPKG{ 0x1000, 0, 0x1000, 1, 0x800, 0x1000, false };
    constexpr DumpConfig CFG_XANIM{ 0, 0, 0, 0, 0, 0, true };
    constexpr DumpConfig CFG_INDEX_PTRS{ 0x200, 0, 0x200, 0, 0, 0, true };

    // sizes from the pool info of the game (code/bo7_poolinfo.csv), they must match the exe
    utils::MapAdder<ImplWorker, SatHashAssetType, Worker> implWeapon{
        GetWorkers(), SatHashAssetType::SATH_ASSET_WEAPON, (size_t)0x568, SatHashAssetType::SATH_ASSET_WEAPON,
        "weapon", CFG_WEAPON
    };
    utils::MapAdder<ImplWorker, SatHashAssetType, Worker> implAttachment{
        GetWorkers(), SatHashAssetType::SATH_ASSET_ATTACHMENT, (size_t)0xe10, SatHashAssetType::SATH_ASSET_ATTACHMENT,
        "attachment", CFG_ATTACHMENT
    };
    utils::MapAdder<ImplWorker, SatHashAssetType, Worker> implWeaponTunables{
        GetWorkers(), SatHashAssetType::SATH_ASSET_WEAPONTUNABLES, (size_t)0x5e68,
        SatHashAssetType::SATH_ASSET_WEAPONTUNABLES, "weapontunables", CFG_TUNABLES
    };
    utils::MapAdder<ImplWorker, SatHashAssetType, Worker> implWeaponBlueprint{
        GetWorkers(), SatHashAssetType::SATH_ASSET_WEAPONBLUEPRINT, (size_t)0x200,
        SatHashAssetType::SATH_ASSET_WEAPONBLUEPRINT, "weaponblueprint", CFG_BLUEPRINT
    };
    utils::MapAdder<ImplWorker, SatHashAssetType, Worker> implAttachmentBlueprint{
        GetWorkers(), SatHashAssetType::SATH_ASSET_ATTACHMENTBLUEPRINT, (size_t)0x1a0,
        SatHashAssetType::SATH_ASSET_ATTACHMENTBLUEPRINT, "attachmentblueprint", CFG_BLUEPRINT
    };
    utils::MapAdder<ImplWorker, SatHashAssetType, Worker> implAnimPkg{
        GetWorkers(), SatHashAssetType::SATH_ASSET_ANIMPKG, (size_t)0x6d0, SatHashAssetType::SATH_ASSET_ANIMPKG,
        "animpkg", CFG_ANIMPKG
    };
    utils::MapAdder<ImplWorker, SatHashAssetType, Worker> implXAnim{
        GetWorkers(), SatHashAssetType::SATH_ASSET_XANIM, (size_t)0x80, SatHashAssetType::SATH_ASSET_XANIM, "xanim",
        CFG_XANIM
    };
    utils::MapAdder<ImplWorker, SatHashAssetType, Worker> implXAnimSet{
        GetWorkers(), SatHashAssetType::SATH_ASSET_XANIMSET, (size_t)0x80, SatHashAssetType::SATH_ASSET_XANIMSET,
        "xanimset", CFG_INDEX_PTRS
    };
    utils::MapAdder<ImplWorker, SatHashAssetType, Worker> implXAnimSetAlias{
        GetWorkers(), SatHashAssetType::SATH_ASSET_XANIMSETALIAS, (size_t)0x30,
        SatHashAssetType::SATH_ASSET_XANIMSETALIAS, "xanimsetalias", CFG_INDEX_PTRS
    };
    // not in the acts enum yet; the value is the hash of the pool name like every other entry
    utils::MapAdder<ImplWorker, SatHashAssetType, Worker> implWeaponArchetype{
        GetWorkers(), static_cast<SatHashAssetType>(hash::HashX32("weaponarchetype")), (size_t)0x28,
        static_cast<SatHashAssetType>(hash::HashX32("weaponarchetype")), "weaponarchetype", CFG_INDEX_PTRS
    };
} // namespace
