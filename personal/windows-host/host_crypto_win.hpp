// JerisLink Windows host: CNG behind host_auth.hpp's crypto hooks.
//
// The viewer's own primitives (windows-client/conn_auth.hpp and
// udp_tag.hpp) do the work, so host and viewer share one implementation of
// PBKDF2, HMAC-SHA256 and the UDP tags; auth_test checks it against
// personal/protocol/auth_vectors.json.
#pragma once

#include "host_auth.hpp"

#include "../windows-client/conn_auth.hpp"
#include "../windows-client/udp_tag.hpp"

#include <cstring>
#include <memory>

namespace jlh::auth::win {

// HmacFn: one HMAC-SHA256 over the concatenated parts. A fresh CNG hash
// per call (AUTH only: four MACs per attempt).
inline bool hmac(const uint8_t* key, size_t keyLen, const Part* parts, size_t nParts, Mac& out) {
    static BCRYPT_ALG_HANDLE alg = [] {
        BCRYPT_ALG_HANDLE a = nullptr;
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&a, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
            return BCRYPT_ALG_HANDLE(nullptr);
        return a;
    }();
    out.fill(0);
    if (!alg) return false;
    BCRYPT_HASH_HANDLE h = nullptr;
    if (!NT_SUCCESS(BCryptCreateHash(alg, &h, nullptr, 0, const_cast<PUCHAR>(key), ULONG(keyLen), 0))) return false;
    bool ok = true;
    for (size_t i = 0; i < nParts && ok; ++i)
        if (parts[i].n) ok = NT_SUCCESS(BCryptHashData(h, const_cast<PUCHAR>(parts[i].p), ULONG(parts[i].n), 0));
    ok = ok && NT_SUCCESS(BCryptFinishHash(h, out.data(), ULONG(out.size()), 0));
    BCryptDestroyHash(h);
    if (!ok) out.fill(0);
    return ok;
}

inline bool random(uint8_t* p, size_t n) { return jl::auth::randomBytes(p, n); }

// K from a typed password (the settings window): NFC, UTF-8, PBKDF2.
inline std::optional<Key> deriveKey(const std::wstring& password, const Salt& salt, uint32_t iterations) {
    const auto k = jl::auth::deriveKey(password, salt.data(), salt.size(), iterations);
    if (!k) return std::nullopt;
    Key out{};
    std::memcpy(out.data(), k->data(), out.size());
    return out;
}

// The session's two taggers: seal h2v, verify v2h.
class CngUdpTags : public UdpTags {
public:
    explicit CngUdpTags(const jl::udptag::SessionKey& k) : sealer_(k, true), verifier_(k, false) {}
    bool ok() const { return sealer_.ok() && verifier_.ok(); }
    size_t seal(const uint8_t* p, size_t n, uint8_t* out) const override { return sealer_.seal(p, n, out); }
    bool verify(const uint8_t* p, size_t n) const override { return verifier_.verify(p, n); }

private:
    jl::udptag::Tagger sealer_, verifier_;
};

inline UdpTagsFactory tagsFactory() {
    return [](const Key& k) -> std::shared_ptr<const UdpTags> {
        jl::udptag::SessionKey sk{};
        std::memcpy(sk.data(), k.data(), sk.size());
        auto t = std::make_shared<CngUdpTags>(sk);
        wipe(sk.data(), sk.size());
        if (!t->ok()) return nullptr;
        return t;
    };
}

}  // namespace jlh::auth::win
