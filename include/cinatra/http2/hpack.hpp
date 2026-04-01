#pragma once
#include <array>
#include <cstdint>
#include <deque>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// HPACK – Header Compression for HTTP/2 (RFC 7541)
// Phase 1: static table + dynamic table, no Huffman encoding.
namespace cinatra::http2 {

struct header_field {
  std::string name;
  std::string value;
};

// ── Static table (RFC 7541 Appendix A) ──────────────────────────────────────
// Index starts at 1; index 0 is unused (placeholder).
struct static_entry {
  std::string_view name;
  std::string_view value;
};

inline constexpr std::array<static_entry, 62> HPACK_STATIC_TABLE = {{
    {"", ""},                                          // 0 – unused
    {":authority",                  ""},               // 1
    {":method",                     "GET"},            // 2
    {":method",                     "POST"},           // 3
    {":path",                       "/"},              // 4
    {":path",                       "/index.html"},    // 5
    {":scheme",                     "http"},           // 6
    {":scheme",                     "https"},          // 7
    {":status",                     "200"},            // 8
    {":status",                     "204"},            // 9
    {":status",                     "206"},            // 10
    {":status",                     "304"},            // 11
    {":status",                     "400"},            // 12
    {":status",                     "404"},            // 13
    {":status",                     "500"},            // 14
    {"accept-charset",              ""},               // 15
    {"accept-encoding",             "gzip, deflate"},  // 16
    {"accept-language",             ""},               // 17
    {"accept-ranges",               ""},               // 18
    {"accept",                      ""},               // 19
    {"access-control-allow-origin", ""},               // 20
    {"age",                         ""},               // 21
    {"allow",                       ""},               // 22
    {"authorization",               ""},               // 23
    {"cache-control",               ""},               // 24
    {"content-disposition",         ""},               // 25
    {"content-encoding",            ""},               // 26
    {"content-language",            ""},               // 27
    {"content-length",              ""},               // 28
    {"content-location",            ""},               // 29
    {"content-range",               ""},               // 30
    {"content-type",                ""},               // 31
    {"cookie",                      ""},               // 32
    {"date",                        ""},               // 33
    {"etag",                        ""},               // 34
    {"expect",                      ""},               // 35
    {"expires",                     ""},               // 36
    {"from",                        ""},               // 37
    {"host",                        ""},               // 38
    {"if-match",                    ""},               // 39
    {"if-modified-since",           ""},               // 40
    {"if-none-match",               ""},               // 41
    {"if-range",                    ""},               // 42
    {"if-unmodified-since",         ""},               // 43
    {"last-modified",               ""},               // 44
    {"link",                        ""},               // 45
    {"location",                    ""},               // 46
    {"max-forwards",                ""},               // 47
    {"proxy-authenticate",          ""},               // 48
    {"proxy-authorization",         ""},               // 49
    {"range",                       ""},               // 50
    {"referer",                     ""},               // 51
    {"refresh",                     ""},               // 52
    {"retry-after",                 ""},               // 53
    {"server",                      ""},               // 54
    {"set-cookie",                  ""},               // 55
    {"strict-transport-security",   ""},               // 56
    {"transfer-encoding",           ""},               // 57
    {"user-agent",                  ""},               // 58
    {"vary",                        ""},               // 59
    {"via",                         ""},               // 60
    {"www-authenticate",            ""},               // 61
}};

constexpr size_t STATIC_TABLE_SIZE = 61;  // indices 1..61

// ── Dynamic table ────────────────────────────────────────────────────────────

class dynamic_table {
 public:
  explicit dynamic_table(size_t max_size = 4096) : max_size_(max_size) {}

  // Add entry at front (index 62 after static table)
  void add(std::string name, std::string value) {
    size_t entry_size = name.size() + value.size() + 32;  // RFC 7541 §4.1
    // Evict oldest entries until there is room
    while (!entries_.empty() && current_size_ + entry_size > max_size_) {
      evict();
    }
    if (entry_size <= max_size_) {
      current_size_ += entry_size;
      entries_.push_front({std::move(name), std::move(value)});
    }
  }

  // Lookup by dynamic-table-local index (1-based within dynamic table)
  const header_field& at(size_t local_idx) const {
    return entries_.at(local_idx - 1);
  }

  size_t size() const { return entries_.size(); }

  void set_max_size(size_t s) {
    max_size_ = s;
    while (!entries_.empty() && current_size_ > max_size_) {
      evict();
    }
  }

 private:
  void evict() {
    auto& back = entries_.back();
    current_size_ -= back.name.size() + back.value.size() + 32;
    entries_.pop_back();
  }

  std::deque<header_field> entries_;
  size_t max_size_;
  size_t current_size_ = 0;
};

// ── Integer coding (RFC 7541 §5.1) ──────────────────────────────────────────

// Decode a variable-length integer with `prefix_bits` prefix bits.
// Advances `buf` past the consumed bytes.
// Returns UINT32_MAX on overflow/error.
inline uint32_t decode_integer(std::span<const uint8_t>& buf,
                                uint8_t prefix_bits) {
  if (buf.empty()) return UINT32_MAX;
  uint8_t mask  = uint8_t((1u << prefix_bits) - 1u);
  uint32_t value = buf[0] & mask;
  buf = buf.subspan(1);
  if (value < mask) return value;  // fits in prefix

  uint32_t m = 0;
  while (true) {
    if (buf.empty()) return UINT32_MAX;
    uint8_t b = buf[0];
    buf = buf.subspan(1);
    value += uint32_t(b & 0x7f) << m;
    m += 7;
    if (!(b & 0x80)) break;
    if (m > 28) return UINT32_MAX;  // overflow guard
  }
  return value;
}

// Encode integer with `prefix_bits` prefix bits into `out`.
// `prefix_high_bits` are the already-set high bits of the first byte.
inline void encode_integer(std::vector<uint8_t>& out, uint32_t value,
                            uint8_t prefix_bits, uint8_t prefix_high_bits = 0) {
  uint8_t mask = uint8_t((1u << prefix_bits) - 1u);
  if (value < mask) {
    out.push_back(uint8_t(prefix_high_bits | value));
    return;
  }
  out.push_back(uint8_t(prefix_high_bits | mask));
  value -= mask;
  while (value >= 0x80) {
    out.push_back(uint8_t((value & 0x7f) | 0x80));
    value >>= 7;
  }
  out.push_back(uint8_t(value));
}

// ── String coding (RFC 7541 §5.2) ───────────────────────────────────────────
// Phase 1: Huffman flag = 0 (plain literal).

inline std::string decode_string(std::span<const uint8_t>& buf) {
  if (buf.empty()) throw std::runtime_error("hpack: truncated string");
  bool huffman = (buf[0] & 0x80) != 0;
  uint32_t len = decode_integer(buf, 7);
  if (len > buf.size()) throw std::runtime_error("hpack: string overrun");
  if (huffman) {
    // Phase 1: reject Huffman-encoded strings to keep implementation simple.
    // A proper implementation would decode using the RFC 7541 Appendix B table.
    throw std::runtime_error("hpack: Huffman decoding not supported in Phase 1");
  }
  std::string s(reinterpret_cast<const char*>(buf.data()), len);
  buf = buf.subspan(len);
  return s;
}

inline void encode_string(std::vector<uint8_t>& out, std::string_view s) {
  // H=0 flag: plain literal
  encode_integer(out, uint32_t(s.size()), 7, 0x00);
  out.insert(out.end(),
             reinterpret_cast<const uint8_t*>(s.data()),
             reinterpret_cast<const uint8_t*>(s.data()) + s.size());
}

// ── HPACK decoder ────────────────────────────────────────────────────────────

class hpack_decoder {
 public:
  explicit hpack_decoder(size_t max_dynamic_size = 4096)
      : dyn_(max_dynamic_size) {}

  // Decode a complete header block fragment → list of header fields.
  std::vector<header_field> decode(std::span<const uint8_t> block) {
    std::vector<header_field> headers;
    while (!block.empty()) {
      uint8_t first = block[0];

      if (first & 0x80) {
        // ── Indexed header field (RFC 7541 §6.1) ─────────────────────────
        // 0b1xxxxxxx
        uint32_t idx = decode_integer(block, 7);
        headers.push_back(lookup(idx));

      } else if (first & 0x40) {
        // ── Literal with incremental indexing (RFC 7541 §6.2.1) ──────────
        // 0b01xxxxxx
        uint32_t idx = decode_integer(block, 6);
        std::string name  = idx ? std::string(lookup(idx).name)
                                : decode_string(block);
        std::string value = decode_string(block);
        dyn_.add(name, value);
        headers.push_back({std::move(name), std::move(value)});

      } else if ((first & 0xf0) == 0x20) {
        // ── Dynamic table size update (RFC 7541 §6.3) ────────────────────
        // 0b001xxxxx
        uint32_t new_size = decode_integer(block, 5);
        dyn_.set_max_size(new_size);

      } else {
        // ── Literal without indexing / never indexed (RFC 7541 §6.2.2/6.2.3)
        // 0b0000xxxx / 0b0001xxxx
        uint32_t idx = decode_integer(block, 4);
        std::string name  = idx ? std::string(lookup(idx).name)
                                : decode_string(block);
        std::string value = decode_string(block);
        headers.push_back({std::move(name), std::move(value)});
      }
    }
    return headers;
  }

 private:
  header_field lookup(uint32_t idx) const {
    if (idx == 0) throw std::runtime_error("hpack: index 0 is invalid");
    if (idx <= STATIC_TABLE_SIZE) {
      auto& e = HPACK_STATIC_TABLE[idx];
      return {std::string(e.name), std::string(e.value)};
    }
    size_t local = idx - STATIC_TABLE_SIZE;
    if (local > dyn_.size())
      throw std::runtime_error("hpack: dynamic table index out of range");
    return dyn_.at(local);
  }

  dynamic_table dyn_;
};

// ── HPACK encoder ────────────────────────────────────────────────────────────

class hpack_encoder {
 public:
  // Encode headers → header block bytes.
  // Strategy: indexed if found in static table (name+value match),
  //           literal with incremental indexing otherwise.
  std::vector<uint8_t> encode(
      std::span<const header_field> headers) {
    std::vector<uint8_t> out;
    for (auto& hf : headers) {
      auto [si, full_match] = static_lookup(hf.name, hf.value);
      if (full_match) {
        // Indexed header field (RFC 7541 §6.1): 0b1xxxxxxx
        encode_integer(out, si, 7, 0x80);
      } else if (si != 0) {
        // Literal with incremental indexing, indexed name (§6.2.1): 0b01xxxxxx
        encode_integer(out, si, 6, 0x40);
        encode_string(out, hf.value);
        dyn_.add(hf.name, hf.value);
      } else {
        // Literal with incremental indexing, new name (§6.2.1): 0b01000000
        out.push_back(0x40);
        encode_string(out, hf.name);
        encode_string(out, hf.value);
        dyn_.add(hf.name, hf.value);
      }
    }
    return out;
  }

 private:
  // Returns {static_index, value_also_matches}.
  std::pair<uint32_t, bool> static_lookup(std::string_view name,
                                           std::string_view value) const {
    uint32_t name_only_idx = 0;
    for (uint32_t i = 1; i <= STATIC_TABLE_SIZE; ++i) {
      auto& e = HPACK_STATIC_TABLE[i];
      if (e.name == name) {
        if (e.value == value) return {i, true};
        if (name_only_idx == 0) name_only_idx = i;
      }
    }
    return {name_only_idx, false};
  }

  dynamic_table dyn_;
};

}  // namespace cinatra::http2
