#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// HTTP/2 binary framing layer (RFC 7540)
namespace cinatra::http2 {

// ── Frame types (RFC 7540 §6) ────────────────────────────────────────────────
enum class frame_type : uint8_t {
  data          = 0x0,
  headers       = 0x1,
  priority      = 0x2,
  rst_stream    = 0x3,
  settings      = 0x4,
  push_promise  = 0x5,
  ping          = 0x6,
  goaway        = 0x7,
  window_update = 0x8,
  continuation  = 0x9,
};

// ── Flag bits (meaning varies by frame type) ─────────────────────────────────
namespace flags {
constexpr uint8_t END_STREAM  = 0x1;
constexpr uint8_t ACK         = 0x1;
constexpr uint8_t END_HEADERS = 0x4;
constexpr uint8_t PADDED      = 0x8;
constexpr uint8_t PRIORITY    = 0x20;
}  // namespace flags

// ── Error codes (RFC 7540 §7) ────────────────────────────────────────────────
enum class h2_error_code : uint32_t {
  no_error            = 0x0,
  protocol_error      = 0x1,
  internal_error      = 0x2,
  flow_control_error  = 0x3,
  settings_timeout    = 0x4,
  stream_closed       = 0x5,
  frame_size_error    = 0x6,
  refused_stream      = 0x7,
  cancel              = 0x8,
  compression_error   = 0x9,
  connect_error       = 0xa,
  enhance_your_calm   = 0xb,
  inadequate_security = 0xc,
  http_1_1_required   = 0xd,
};

// ── Settings parameters (RFC 7540 §6.5.2) ───────────────────────────────────
enum class settings_param : uint16_t {
  header_table_size      = 0x1,
  enable_push            = 0x2,
  max_concurrent_streams = 0x3,
  initial_window_size    = 0x4,
  max_frame_size         = 0x5,
  max_header_list_size   = 0x6,
};

struct settings_entry {
  settings_param id;
  uint32_t value;
};

// ── Fixed 9-byte frame header (RFC 7540 §4.1) ───────────────────────────────
struct frame_header {
  uint32_t   length;     // 24-bit payload length
  frame_type type;
  uint8_t    flags;
  uint32_t   stream_id;  // 31-bit; R flag (bit 31) ignored
};

// Parse 9 raw bytes → frame_header
inline frame_header parse_frame_header(
    std::span<const uint8_t, 9> buf) noexcept {
  frame_header h;
  h.length = (uint32_t(buf[0]) << 16) | (uint32_t(buf[1]) << 8) | buf[2];
  h.type   = static_cast<frame_type>(buf[3]);
  h.flags  = buf[4];
  h.stream_id = ((uint32_t(buf[5]) & 0x7f) << 24) |
                 (uint32_t(buf[6]) << 16) |
                 (uint32_t(buf[7]) <<  8) |
                  uint32_t(buf[8]);
  return h;
}

// Serialize frame_header → 9 bytes
inline std::array<uint8_t, 9> serialize_frame_header(
    const frame_header& h) noexcept {
  std::array<uint8_t, 9> buf{};
  buf[0] = uint8_t(h.length >> 16);
  buf[1] = uint8_t(h.length >>  8);
  buf[2] = uint8_t(h.length);
  buf[3] = static_cast<uint8_t>(h.type);
  buf[4] = h.flags;
  buf[5] = uint8_t((h.stream_id >> 24) & 0x7f);
  buf[6] = uint8_t(h.stream_id >> 16);
  buf[7] = uint8_t(h.stream_id >>  8);
  buf[8] = uint8_t(h.stream_id);
  return buf;
}

// ── Frame builders ───────────────────────────────────────────────────────────

// Generic: 9-byte header + arbitrary payload
inline std::string make_frame(frame_type type, uint8_t flags,
                               uint32_t stream_id,
                               std::span<const uint8_t> payload) {
  frame_header h{
      .length    = uint32_t(payload.size()),
      .type      = type,
      .flags     = flags,
      .stream_id = stream_id,
  };
  auto hdr = serialize_frame_header(h);
  std::string out(9 + payload.size(), '\0');
  std::copy(hdr.begin(), hdr.end(), out.begin());
  std::copy(payload.begin(), payload.end(), out.begin() + 9);
  return out;
}

// SETTINGS frame (stream_id must be 0)
inline std::string make_settings_frame(
    std::span<const settings_entry> entries = {}, bool ack = false) {
  std::vector<uint8_t> payload;
  if (!ack) {
    payload.resize(entries.size() * 6);
    for (size_t i = 0; i < entries.size(); ++i) {
      auto id  = uint16_t(entries[i].id);
      auto val = entries[i].value;
      payload[i*6+0] = uint8_t(id  >>  8);
      payload[i*6+1] = uint8_t(id);
      payload[i*6+2] = uint8_t(val >> 24);
      payload[i*6+3] = uint8_t(val >> 16);
      payload[i*6+4] = uint8_t(val >>  8);
      payload[i*6+5] = uint8_t(val);
    }
  }
  uint8_t f = ack ? flags::ACK : 0;
  return make_frame(frame_type::settings, f, 0, payload);
}

// Parse SETTINGS payload → list of entries
inline std::vector<settings_entry> parse_settings_payload(
    std::span<const uint8_t> payload) {
  std::vector<settings_entry> out;
  for (size_t i = 0; i + 6 <= payload.size(); i += 6) {
    uint16_t id  = (uint16_t(payload[i]) << 8) | payload[i+1];
    uint32_t val = (uint32_t(payload[i+2]) << 24) |
                   (uint32_t(payload[i+3]) << 16) |
                   (uint32_t(payload[i+4]) <<  8) |
                    uint32_t(payload[i+5]);
    out.push_back({static_cast<settings_param>(id), val});
  }
  return out;
}

// RST_STREAM frame
inline std::string make_rst_stream(uint32_t stream_id, h2_error_code ec) {
  uint32_t code = uint32_t(ec);
  std::array<uint8_t, 4> payload{
      uint8_t(code >> 24), uint8_t(code >> 16),
      uint8_t(code >>  8), uint8_t(code),
  };
  return make_frame(frame_type::rst_stream, 0, stream_id, payload);
}

// GOAWAY frame (stream_id = 0)
inline std::string make_goaway(uint32_t last_stream_id, h2_error_code ec) {
  uint32_t code = uint32_t(ec);
  std::array<uint8_t, 8> payload{
      uint8_t((last_stream_id >> 24) & 0x7f),
      uint8_t( last_stream_id >> 16),
      uint8_t( last_stream_id >>  8),
      uint8_t( last_stream_id),
      uint8_t(code >> 24), uint8_t(code >> 16),
      uint8_t(code >>  8), uint8_t(code),
  };
  return make_frame(frame_type::goaway, 0, 0, payload);
}

// PING ACK frame
inline std::string make_ping_ack(std::span<const uint8_t, 8> data) {
  return make_frame(frame_type::ping, flags::ACK, 0, data);
}

// WINDOW_UPDATE frame
inline std::string make_window_update(uint32_t stream_id,
                                      uint32_t increment) {
  std::array<uint8_t, 4> payload{
      uint8_t((increment >> 24) & 0x7f),
      uint8_t( increment >> 16),
      uint8_t( increment >>  8),
      uint8_t( increment),
  };
  return make_frame(frame_type::window_update, 0, stream_id, payload);
}

// ── Connection preface ───────────────────────────────────────────────────────
// Client MUST send this 24-byte magic before any frames (RFC 7540 §3.5)
constexpr std::string_view CLIENT_PREFACE =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

}  // namespace cinatra::http2
