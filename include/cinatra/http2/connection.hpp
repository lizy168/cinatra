#pragma once
#include <async_simple/coro/Lazy.h>

#include <asio/ip/tcp.hpp>
#include <functional>
#include <string>
#include <system_error>
#include <unordered_map>
#include <vector>

#include "cinatra/ylt/coro_io/coro_io.hpp"
#include "frame.hpp"
#include "hpack.hpp"

// HTTP/2 server-side connection – Phase 1
// Single coroutine loop: read one frame at a time, handle inline, write
// response synchronously. Handles: preface, SETTINGS, HEADERS, DATA,
// PING, RST_STREAM, GOAWAY, WINDOW_UPDATE (ignored), CONTINUATION.
namespace cinatra::http2 {

// ── Per-stream request and response ─────────────────────────────────────────

struct h2_request {
  std::string method;
  std::string path;
  std::string scheme;
  std::string authority;
  std::string body;
  std::vector<header_field> headers;

  std::string_view get_header(std::string_view name) const {
    for (auto& hf : headers)
      if (hf.name == name) return hf.value;
    return {};
  }
};

struct h2_response {
  int status_code = 200;
  std::string body;
  std::vector<header_field> headers;

  void set_status_and_body(int code, std::string b) {
    status_code = code;
    body        = std::move(b);
  }
  void add_header(std::string name, std::string value) {
    headers.push_back({std::move(name), std::move(value)});
  }
};

using h2_handler =
    std::function<async_simple::coro::Lazy<void>(h2_request&, h2_response&)>;

// ── Connection class ─────────────────────────────────────────────────────────

class coro_http2_connection
    : public std::enable_shared_from_this<coro_http2_connection> {
 public:
  static constexpr uint32_t MAX_FRAME_SIZE = 16384;

  explicit coro_http2_connection(asio::ip::tcp::socket socket,
                                  h2_handler handler)
      : socket_(std::move(socket)), handler_(std::move(handler)) {}

  // Entry point: run the connection until it closes.
  async_simple::coro::Lazy<void> start() {
    if (!co_await read_preface()) co_return;

    // Send server SETTINGS immediately
    std::array<settings_entry, 1> srv_settings{
        settings_entry{settings_param::max_frame_size, MAX_FRAME_SIZE}};
    if (!co_await write_frame(make_settings_frame(srv_settings)))
      co_return;

    // Single read loop: read one frame, handle inline, repeat
    std::array<uint8_t, 9> hdr_buf;
    while (true) {
      // Read 9-byte frame header
      {
        auto buf = asio::buffer(hdr_buf);
        auto [ec, n] = co_await coro_io::async_read(socket_, buf, 9);
        if (ec || n != 9) co_return;
      }

      auto hdr = parse_frame_header(hdr_buf);
      if (hdr.length > MAX_FRAME_SIZE) {
        co_await write_frame(
            make_goaway(last_stream_id_, h2_error_code::frame_size_error));
        co_return;
      }

      // Read payload
      payload_buf_.resize(hdr.length);
      if (hdr.length > 0) {
        auto buf = asio::buffer(payload_buf_);
        auto [ec, n] = co_await coro_io::async_read(socket_, buf, hdr.length);
        if (ec || n != hdr.length) co_return;
      }

      std::span<const uint8_t> payload(payload_buf_.data(), hdr.length);
      if (!co_await handle_frame(hdr, payload)) co_return;
    }
  }

 private:
  // ── Internal stream state ─────────────────────────────────────────────────

  struct stream_state {
    h2_request           req;
    std::vector<uint8_t> hdr_block_buf;
    bool                 end_stream  = false;
    bool                 end_headers = false;
  };

  // ── Preface ───────────────────────────────────────────────────────────────

  async_simple::coro::Lazy<bool> read_preface() {
    std::array<uint8_t, 24> buf;
    auto abuf = asio::buffer(buf);
    auto [ec, n] = co_await coro_io::async_read(
        socket_, abuf, CLIENT_PREFACE.size());
    if (ec || n != CLIENT_PREFACE.size()) co_return false;
    co_return std::string_view(reinterpret_cast<const char*>(buf.data()), n)
              == CLIENT_PREFACE;
  }

  // ── Frame writer ─────────────────────────────────────────────────────────

  async_simple::coro::Lazy<bool> write_frame(std::string data) {
    auto [ec, n] = co_await coro_io::async_write(
        socket_, asio::buffer(data));
    co_return !ec;
  }

  // ── Frame dispatcher ─────────────────────────────────────────────────────

  async_simple::coro::Lazy<bool> handle_frame(
      const frame_header& hdr, std::span<const uint8_t> payload) {
    switch (hdr.type) {
      case frame_type::settings:      co_return co_await on_settings(hdr, payload);
      case frame_type::headers:       co_return co_await on_headers(hdr, payload);
      case frame_type::continuation:  co_return co_await on_continuation(hdr, payload);
      case frame_type::data:          co_return co_await on_data(hdr, payload);
      case frame_type::ping:          co_return co_await on_ping(hdr, payload);
      case frame_type::rst_stream:    streams_.erase(hdr.stream_id); co_return true;
      case frame_type::goaway:        co_return false;
      case frame_type::window_update: co_return true;  // Phase 1: ignore
      default:                        co_return true;
    }
  }

  // ── SETTINGS ─────────────────────────────────────────────────────────────

  async_simple::coro::Lazy<bool> on_settings(
      const frame_header& hdr, std::span<const uint8_t> payload) {
    if (hdr.stream_id != 0) {
      co_await write_frame(
          make_goaway(last_stream_id_, h2_error_code::protocol_error));
      co_return false;
    }
    if (!(hdr.flags & flags::ACK))
      co_return co_await write_frame(make_settings_frame({}, true));
    co_return true;
  }

  // ── HEADERS ──────────────────────────────────────────────────────────────

  async_simple::coro::Lazy<bool> on_headers(
      const frame_header& hdr, std::span<const uint8_t> payload) {
    if (hdr.stream_id == 0) {
      co_await write_frame(
          make_goaway(0, h2_error_code::protocol_error));
      co_return false;
    }
    last_stream_id_ = std::max(last_stream_id_, hdr.stream_id);

    auto& st = streams_[hdr.stream_id];
    auto frag = strip_padding_priority(hdr, payload);
    st.hdr_block_buf.insert(st.hdr_block_buf.end(), frag.begin(), frag.end());
    st.end_stream  = (hdr.flags & flags::END_STREAM)  != 0;
    st.end_headers = (hdr.flags & flags::END_HEADERS) != 0;

    if (st.end_headers) {
      if (!decode_headers(st)) co_return false;
      if (st.end_stream) {
        co_return co_await dispatch_stream(hdr.stream_id, st);
      }
    }
    co_return true;
  }

  // ── CONTINUATION ─────────────────────────────────────────────────────────

  async_simple::coro::Lazy<bool> on_continuation(
      const frame_header& hdr, std::span<const uint8_t> payload) {
    auto it = streams_.find(hdr.stream_id);
    if (it == streams_.end()) {
      co_await write_frame(
          make_goaway(last_stream_id_, h2_error_code::protocol_error));
      co_return false;
    }
    auto& st = it->second;
    st.hdr_block_buf.insert(st.hdr_block_buf.end(),
                             payload.begin(), payload.end());
    if (hdr.flags & flags::END_HEADERS) {
      st.end_headers = true;
      if (!decode_headers(st)) co_return false;
      if (st.end_stream)
        co_return co_await dispatch_stream(hdr.stream_id, st);
    }
    co_return true;
  }

  // ── DATA ─────────────────────────────────────────────────────────────────

  async_simple::coro::Lazy<bool> on_data(
      const frame_header& hdr, std::span<const uint8_t> payload) {
    auto it = streams_.find(hdr.stream_id);
    if (it == streams_.end()) {
      co_return co_await write_frame(
          make_rst_stream(hdr.stream_id, h2_error_code::stream_closed));
    }
    auto& st = it->second;
    auto data = payload;
    if ((hdr.flags & flags::PADDED) && !data.empty()) {
      uint8_t pad = data[0];
      data = data.subspan(1);
      if (pad <= data.size()) data = data.subspan(0, data.size() - pad);
    }
    st.req.body.append(reinterpret_cast<const char*>(data.data()), data.size());
    if (hdr.flags & flags::END_STREAM)
      co_return co_await dispatch_stream(hdr.stream_id, st);
    co_return true;
  }

  // ── PING ─────────────────────────────────────────────────────────────────

  async_simple::coro::Lazy<bool> on_ping(
      const frame_header& hdr, std::span<const uint8_t> payload) {
    if (hdr.flags & flags::ACK) co_return true;
    if (payload.size() != 8) co_return false;
    std::array<uint8_t, 8> data;
    std::copy_n(payload.begin(), 8, data.begin());
    co_return co_await write_frame(make_ping_ack(data));
  }

  // ── Handler dispatch ─────────────────────────────────────────────────────

  async_simple::coro::Lazy<bool> dispatch_stream(uint32_t stream_id,
                                                   stream_state& st) {
    h2_response resp;
    try {
      co_await handler_(st.req, resp);
    } catch (...) {
      resp.set_status_and_body(500, "Internal Server Error");
    }
    streams_.erase(stream_id);
    co_return co_await send_response(stream_id, resp);
  }

  // ── Response serialization ───────────────────────────────────────────────

  async_simple::coro::Lazy<bool> send_response(uint32_t stream_id,
                                                 const h2_response& resp) {
    std::vector<header_field> resp_hdrs;
    resp_hdrs.push_back({":status", std::to_string(resp.status_code)});
    if (!resp.body.empty())
      resp_hdrs.push_back({"content-length", std::to_string(resp.body.size())});
    for (auto& hf : resp.headers) resp_hdrs.push_back(hf);

    auto hdr_block = encoder_.encode(resp_hdrs);
    uint8_t hdr_flags = flags::END_HEADERS;
    if (resp.body.empty()) hdr_flags |= flags::END_STREAM;

    std::string out = make_frame(frame_type::headers, hdr_flags, stream_id,
                                  std::span<const uint8_t>(hdr_block));
    if (!resp.body.empty()) {
      size_t offset = 0;
      while (offset < resp.body.size()) {
        size_t chunk =
            std::min<size_t>(resp.body.size() - offset, MAX_FRAME_SIZE);
        bool last = (offset + chunk == resp.body.size());
        auto span = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(resp.body.data()) + offset, chunk);
        out += make_frame(frame_type::data,
                           last ? flags::END_STREAM : uint8_t(0),
                           stream_id, span);
        offset += chunk;
      }
    }
    co_return co_await write_frame(std::move(out));
  }

  // ── Utilities ────────────────────────────────────────────────────────────

  static std::span<const uint8_t> strip_padding_priority(
      const frame_header& hdr, std::span<const uint8_t> payload) {
    uint8_t pad_len = 0;
    if ((hdr.flags & flags::PADDED) && !payload.empty()) {
      pad_len = payload[0];
      payload = payload.subspan(1);
    }
    if ((hdr.flags & flags::PRIORITY) && payload.size() >= 5)
      payload = payload.subspan(5);
    if (pad_len > 0 && pad_len <= payload.size())
      payload = payload.subspan(0, payload.size() - pad_len);
    return payload;
  }

  bool decode_headers(stream_state& st) {
    try {
      auto decoded = decoder_.decode(st.hdr_block_buf);
      st.hdr_block_buf.clear();
      for (auto& hf : decoded) {
        if      (hf.name == ":method")    st.req.method    = hf.value;
        else if (hf.name == ":path")      st.req.path      = hf.value;
        else if (hf.name == ":scheme")    st.req.scheme    = hf.value;
        else if (hf.name == ":authority") st.req.authority = hf.value;
        else st.req.headers.push_back(hf);
      }
      return true;
    } catch (...) {
      auto ec = make_goaway(last_stream_id_, h2_error_code::compression_error);
      // Fire and forget (best-effort)
      async_simple::coro::syncAwait(write_frame(std::move(ec)));
      return false;
    }
  }

  // ── Members ───────────────────────────────────────────────────────────────

  asio::ip::tcp::socket                      socket_;
  h2_handler                                 handler_;
  hpack_decoder                              decoder_;
  hpack_encoder                              encoder_;
  std::unordered_map<uint32_t, stream_state> streams_;
  uint32_t                                   last_stream_id_ = 0;
  std::vector<uint8_t>                       payload_buf_;
};

}  // namespace cinatra::http2
