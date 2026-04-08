#pragma once
#include <async_simple/Executor.h>
#include <async_simple/coro/ConditionVariable.h>
#include <async_simple/coro/Lazy.h>
#include <async_simple/coro/Mutex.h>

#include <asio/ip/tcp.hpp>
#include <atomic>
#include <charconv>
#include <functional>
#include <optional>
#include <regex>
#include <string>
#include <system_error>
#include <unordered_map>
#include <vector>

#include "cinatra/ylt/coro_io/coro_io.hpp"
#include "frame.hpp"
#include "hpack.hpp"

// HTTP/2 server-side connection – Phase 2
// Single coroutine loop: read one frame at a time, handle inline, write
// response synchronously. Handles: preface, SETTINGS, HEADERS, DATA,
// PING, RST_STREAM, GOAWAY, WINDOW_UPDATE, CONTINUATION.
// Phase 2 additions: CONTINUATION interleaving guard, stream lifecycle
// state machine, proper RST_STREAM/GOAWAY validation.
namespace cinatra::http2 {

// ── Per-stream request and response ─────────────────────────────────────────

struct h2_request {
  std::string method;
  std::string path;
  std::string scheme;
  std::string authority;
  std::string protocol;
  std::string body;
  std::vector<header_field> headers;
  std::vector<header_field> trailers;
  std::unordered_map<std::string, std::string> params_;
  std::smatch matches_;

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

enum class header_block_kind {
  initial,
  trailer,
};

inline bool contains_invalid_header_name(std::string_view value) {
  if (value.empty()) return true;
  for (unsigned char ch : value) {
    if (ch <= 0x20 || ch == 0x7f || (ch >= 'A' && ch <= 'Z'))
      return true;
  }
  return false;
}

inline bool contains_invalid_header_value(std::string_view value) {
  for (unsigned char ch : value) {
    if (ch == '\0' || ch == '\r' || ch == '\n')
      return true;
  }
  return false;
}

inline std::optional<uint64_t> parse_content_length(std::string_view value) {
  if (value.empty()) return std::nullopt;
  uint64_t result = 0;
  auto* begin = value.data();
  auto* end = value.data() + value.size();
  auto [ptr, err] = std::from_chars(begin, end, result);
  if (err != std::errc{} || ptr != end)
    return std::nullopt;
  return result;
}

inline std::string_view trim_optional_whitespace(std::string_view value) {
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
    value.remove_prefix(1);
  while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
    value.remove_suffix(1);
  return value;
}

inline bool ascii_iequals(std::string_view lhs, std::string_view rhs) {
  if (lhs.size() != rhs.size()) return false;
  for (size_t i = 0; i < lhs.size(); ++i) {
    unsigned char l = static_cast<unsigned char>(lhs[i]);
    unsigned char r = static_cast<unsigned char>(rhs[i]);
    if (l >= 'A' && l <= 'Z') l = static_cast<unsigned char>(l - 'A' + 'a');
    if (r >= 'A' && r <= 'Z') r = static_cast<unsigned char>(r - 'A' + 'a');
    if (l != r) return false;
  }
  return true;
}

inline bool is_connection_specific_header(std::string_view name) {
  return name == "connection" || name == "keep-alive" ||
         name == "proxy-connection" || name == "transfer-encoding" ||
         name == "upgrade";
}

inline bool validate_request_regular_header(std::string_view name,
                                            std::string_view value,
                                            header_block_kind kind) {
  if (is_connection_specific_header(name)) return false;
  if (name == "te") {
    return kind == header_block_kind::initial &&
           ascii_iequals(trim_optional_whitespace(value), "trailers");
  }
  if (kind == header_block_kind::trailer && name == "content-length")
    return false;
  return true;
}

inline bool validate_response_regular_header(std::string_view name,
                                             std::string_view value,
                                             header_block_kind kind) {
  if (is_connection_specific_header(name) || name == "te") return false;
  if (kind == header_block_kind::trailer && name == "content-length")
    return false;
  return true;
}

using h2_handler =
    std::function<async_simple::coro::Lazy<void>(h2_request&, h2_response&)>;

// ── Connection class ─────────────────────────────────────────────────────────

class coro_http2_connection
    : public std::enable_shared_from_this<coro_http2_connection> {
 public:
  static constexpr uint32_t MAX_FRAME_SIZE = 16384;
  static constexpr uint32_t DEFAULT_WINDOW_SIZE = 65535;
  static constexpr uint32_t MAX_WINDOW_SIZE = 0x7fffffff;
  static constexpr uint32_t MAX_ALLOWED_FRAME_SIZE = 16777215;
  static constexpr uint32_t DEFAULT_MAX_CONCURRENT_STREAMS = 100;

  explicit coro_http2_connection(asio::ip::tcp::socket socket,
                                  h2_handler handler,
                                  async_simple::Executor* executor = nullptr)
      : socket_(std::move(socket)),
        handler_(std::move(handler)),
        executor_(executor) {}

  void set_quit_callback(std::function<void()> cb) {
    quit_callback_ = std::move(cb);
  }

  void set_enable_connect_protocol(bool enabled) {
    enable_connect_protocol_ = enabled;
  }

  void force_close() {
    close_send_waiters();
    std::error_code ignored;
    socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
    socket_.close(ignored);
  }

  // Initiate graceful shutdown: send GOAWAY, stop accepting new streams.
  async_simple::coro::Lazy<void> graceful_shutdown() {
    if (!going_away_) {
      going_away_ = true;
      if (!co_await write_frame(
              make_goaway(last_stream_id_, h2_error_code::no_error))) {
        force_close();
        co_return;
      }
    }
    finish_graceful_shutdown();
  }

  // Entry point: run the connection until it closes.
  async_simple::coro::Lazy<void> start() {
    struct scoped_notify {
      coro_http2_connection* self;
      ~scoped_notify() {
        self->close_send_waiters();
        self->notify_quit();
      }
    } on_exit{this};

    if (executor_ == nullptr)
      executor_ = co_await async_simple::CurrentExecutor{};
    if (!co_await read_preface()) co_return;

    // Send server SETTINGS immediately
    std::array<settings_entry, 5> srv_settings{
        settings_entry{settings_param::header_table_size, 4096},
        settings_entry{settings_param::max_concurrent_streams,
                       local_max_concurrent_streams_},
        settings_entry{settings_param::initial_window_size,
                       local_initial_window_size_},
        settings_entry{settings_param::max_frame_size, MAX_FRAME_SIZE},
        settings_entry{settings_param::enable_connect_protocol,
                       enable_connect_protocol_ ? 1u : 0u}};
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
      if (!peer_settings_received_) {
        if (hdr.type != frame_type::settings || hdr.stream_id != 0 ||
            (hdr.flags & flags::ACK)) {
          co_await write_frame(
              make_goaway(last_stream_id_, h2_error_code::protocol_error));
          std::error_code ignored;
          socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ignored);
          co_return;
        }
      }
      if (hdr.length > MAX_FRAME_SIZE) {
        co_await write_frame(
            make_goaway(last_stream_id_, h2_error_code::frame_size_error));
        std::error_code ignored;
        socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ignored);
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
      if (!co_await handle_frame(hdr, payload)) {
        // Graceful TCP shutdown so GOAWAY reaches the peer before close.
        std::error_code ignored;
        socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ignored);
        co_return;
      }
      cleanup_done_streams();
    }
  }

 private:
  // ── Stream lifecycle (RFC 7540 §5.1) ─────────────────────────────────────

  enum class stream_lifecycle {
    idle,
    open,
    half_closed_remote,  // client sent END_STREAM
    half_closed_local,   // server sent END_STREAM
    closed,
  };

  struct stream_state {
    h2_request           req;
    std::vector<uint8_t> hdr_block_buf;
    bool                 end_stream  = false;
    bool                 end_headers = false;
    bool                 initial_headers_received = false;
    bool                 trailing_headers_received = false;
    stream_lifecycle     state       = stream_lifecycle::idle;
    int32_t              recv_window =
        static_cast<int32_t>(DEFAULT_WINDOW_SIZE);
    uint32_t             recv_pending = 0;  // bytes consumed but not yet ACKed
    int32_t              send_window =
        static_cast<int32_t>(DEFAULT_WINDOW_SIZE);
    bool                 dispatch_started = false;
    bool                 dispatch_done   = false;  // set by dispatch_stream
    std::optional<uint64_t> content_length;
  };

  enum class flow_control_result {
    ok,
    stream_error,
    connection_error,
  };

  enum class header_decode_result {
    ok,
    stream_error,
    connection_error,
  };

  struct payload_view_result {
    bool ok = false;
    bool stream_error = false;  // if true, caller should RST_STREAM not GOAWAY
    std::span<const uint8_t> payload{};
    h2_error_code error_code = h2_error_code::protocol_error;
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
    auto lock = co_await write_mutex_.coScopedLock();
    auto [ec, n] = co_await coro_io::async_write(
        socket_, asio::buffer(data));
    co_return !ec && n == data.size();
  }

  async_simple::coro::Lazy<bool> write_frame_locked(std::string_view data) {
    auto [ec, n] = co_await coro_io::async_write(
        socket_, asio::buffer(data));
    co_return !ec && n == data.size();
  }

  async_simple::coro::Lazy<bool> write_header_block(
      uint32_t stream_id, std::span<const header_field> headers,
      uint8_t first_frame_flags) {
    auto header_lock = co_await header_mutex_.coScopedLock();
    auto write_lock = co_await write_mutex_.coScopedLock();

    auto header_block = encoder_.encode(headers);
    auto frames = make_header_block_frames(
        stream_id, std::span<const uint8_t>(header_block), first_frame_flags,
        std::min(peer_max_frame_size_, MAX_ALLOWED_FRAME_SIZE));
    for (auto& frame : frames) {
      if (!co_await write_frame_locked(frame))
        co_return false;
    }
    co_return true;
  }

  // ── Frame dispatcher ─────────────────────────────────────────────────────

  async_simple::coro::Lazy<bool> handle_frame(
      const frame_header& hdr, std::span<const uint8_t> payload) {
    // RFC 7540 §6.10: while a header block is incomplete, only CONTINUATION
    // frames for the same stream are allowed. Anything else is PROTOCOL_ERROR.
    if (pending_continuation_stream_ != 0) {
      if (hdr.type != frame_type::continuation ||
          hdr.stream_id != pending_continuation_stream_) {
        co_await write_frame(
            make_goaway(last_stream_id_, h2_error_code::protocol_error));
        co_return false;
      }
    }

    switch (hdr.type) {
      case frame_type::settings:      co_return co_await on_settings(hdr, payload);
      case frame_type::headers:       co_return co_await on_headers(hdr, payload);
      case frame_type::continuation:  co_return co_await on_continuation(hdr, payload);
      case frame_type::data:          co_return co_await on_data(hdr, payload);
      case frame_type::priority:      co_return co_await on_priority(hdr, payload);
      case frame_type::ping:          co_return co_await on_ping(hdr, payload);
      case frame_type::push_promise:  co_return co_await on_push_promise(hdr, payload);
      case frame_type::rst_stream:    co_return co_await on_rst_stream(hdr, payload);
      case frame_type::goaway:        co_return co_await on_goaway(hdr, payload);
      case frame_type::window_update: co_return co_await on_window_update(hdr, payload);
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
    if (hdr.flags & flags::ACK) {
      if (hdr.length != 0) {
        co_await write_frame(
            make_goaway(last_stream_id_, h2_error_code::frame_size_error));
        co_return false;
      }
      co_return true;
    }

    if ((hdr.length % 6) != 0) {
      co_await write_frame(
          make_goaway(last_stream_id_, h2_error_code::frame_size_error));
      co_return false;
    }

    for (auto setting : parse_settings_payload(payload)) {
      switch (setting.id) {
        case settings_param::header_table_size:
          encoder_.set_max_dynamic_table_size(setting.value);
          break;
        case settings_param::enable_push:
          if (setting.value > 1) {
            co_await write_frame(
                make_goaway(last_stream_id_, h2_error_code::protocol_error));
            co_return false;
          }
          break;
        case settings_param::max_concurrent_streams:
          peer_max_concurrent_streams_ = setting.value;
          break;
        case settings_param::initial_window_size:
          if (setting.value > MAX_WINDOW_SIZE) {
            co_await write_frame(
                make_goaway(last_stream_id_, h2_error_code::flow_control_error));
            co_return false;
          }
          {
            int64_t delta = static_cast<int64_t>(setting.value) -
                            static_cast<int64_t>(peer_initial_window_size_);
            for (auto& [id, st] : streams_) {
              int64_t next = static_cast<int64_t>(st->send_window) + delta;
              if (next < 0 || next > MAX_WINDOW_SIZE) {
                co_await write_frame(make_goaway(
                    last_stream_id_, h2_error_code::flow_control_error));
                co_return false;
              }
              st->send_window = static_cast<int32_t>(next);
            }
          }
          peer_initial_window_size_ = setting.value;
          send_window_cv_.notifyAll();
          break;
        case settings_param::max_frame_size:
          if (setting.value < MAX_FRAME_SIZE ||
              setting.value > MAX_ALLOWED_FRAME_SIZE) {
            co_await write_frame(
                make_goaway(last_stream_id_, h2_error_code::protocol_error));
            co_return false;
          }
          peer_max_frame_size_ = setting.value;
          break;
        case settings_param::max_header_list_size:
          peer_max_header_list_size_ = setting.value;
          break;
        case settings_param::enable_connect_protocol:
          if (setting.value > 1) {
            co_await write_frame(
                make_goaway(last_stream_id_, h2_error_code::protocol_error));
            co_return false;
          }
          peer_enable_connect_protocol_ = setting.value == 1;
          break;
      }
    }

    peer_settings_received_ = true;
    co_return co_await write_frame(make_settings_frame({}, true));
  }

  // ── WINDOW_UPDATE ────────────────────────────────────────────────────────

  async_simple::coro::Lazy<bool> on_window_update(
      const frame_header& hdr, std::span<const uint8_t> payload) {
    if (hdr.length != 4) {
      co_await write_frame(
          make_goaway(last_stream_id_, h2_error_code::frame_size_error));
      co_return false;
    }

    uint32_t increment = ((uint32_t(payload[0]) & 0x7f) << 24) |
                         (uint32_t(payload[1]) << 16) |
                         (uint32_t(payload[2]) << 8) |
                         uint32_t(payload[3]);
    if (increment == 0) {
      if (hdr.stream_id == 0) {
        co_await write_frame(
            make_goaway(last_stream_id_, h2_error_code::protocol_error));
        co_return false;
      }
      abort_stream(hdr.stream_id);
      co_return co_await write_frame(
          make_rst_stream(hdr.stream_id, h2_error_code::protocol_error));
    }
    if (hdr.stream_id == 0) {
      if (increment >
          static_cast<uint32_t>(MAX_WINDOW_SIZE - connection_send_window_)) {
        co_await write_frame(
            make_goaway(last_stream_id_, h2_error_code::flow_control_error));
        co_return false;
      }
      connection_send_window_ += static_cast<int32_t>(increment);
    }
    else if (auto it = streams_.find(hdr.stream_id); it != streams_.end()) {
      if (increment >
          static_cast<uint32_t>(MAX_WINDOW_SIZE - it->second->send_window)) {
        abort_stream(hdr.stream_id);
        co_return co_await write_frame(
            make_rst_stream(hdr.stream_id, h2_error_code::flow_control_error));
      }
      it->second->send_window += static_cast<int32_t>(increment);
    }
    send_window_cv_.notifyAll();
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

    // RFC 7540 §5.1.1: client-initiated stream IDs must be odd and strictly
    // greater than any previously opened client stream.
    bool is_new = streams_.find(hdr.stream_id) == streams_.end();
    if (is_new) {
      if ((hdr.stream_id & 1u) == 0 || hdr.stream_id <= last_stream_id_) {
        co_await write_frame(
            make_goaway(last_stream_id_, h2_error_code::protocol_error));
        co_return false;
      }
      if (streams_.size() >= local_max_concurrent_streams_) {
        co_return co_await write_frame(
            make_rst_stream(hdr.stream_id, h2_error_code::refused_stream));
      }
      if (going_away_) {
        // Reject new streams after GOAWAY.
        co_return co_await write_frame(
            make_rst_stream(hdr.stream_id, h2_error_code::refused_stream));
      }
      last_stream_id_ = hdr.stream_id;
    }

    auto& st = streams_[hdr.stream_id];
    if (is_new) {
      st = std::make_shared<stream_state>();
      st->state = stream_lifecycle::open;
      st->recv_window = static_cast<int32_t>(local_initial_window_size_);
      st->send_window = static_cast<int32_t>(peer_initial_window_size_);
    }
    else if (!st->initial_headers_received || st->trailing_headers_received ||
             st->dispatch_started || st->state != stream_lifecycle::open) {
      abort_stream(hdr.stream_id);
      co_return co_await write_frame(
          make_rst_stream(hdr.stream_id, h2_error_code::protocol_error));
    }

    auto frag = strip_padding_priority(hdr, payload);
    if (!frag.ok) {
      if (frag.stream_error) {
        abort_stream(hdr.stream_id);
        co_return co_await write_frame(
            make_rst_stream(hdr.stream_id, frag.error_code));
      }
      co_await write_frame(make_goaway(last_stream_id_, frag.error_code));
      co_return false;
    }
    st->hdr_block_buf.insert(
        st->hdr_block_buf.end(), frag.payload.begin(), frag.payload.end());
    st->end_stream  = (hdr.flags & flags::END_STREAM)  != 0;
    st->end_headers = (hdr.flags & flags::END_HEADERS) != 0;

    auto block_kind = st->initial_headers_received ? header_block_kind::trailer
                                                   : header_block_kind::initial;
    if (block_kind == header_block_kind::trailer && !st->end_stream) {
      abort_stream(hdr.stream_id);
      co_return co_await write_frame(
          make_rst_stream(hdr.stream_id, h2_error_code::protocol_error));
    }

    if (!st->end_headers) {
      pending_continuation_stream_ = hdr.stream_id;
      co_return true;
    }

    pending_continuation_stream_ = 0;
    auto decode_result = decode_headers(*st, block_kind);
    if (decode_result != header_decode_result::ok) {
      if (decode_result == header_decode_result::connection_error) {
        auto ec = pending_connection_error_.value_or(
            h2_error_code::protocol_error);
        pending_connection_error_.reset();
        co_await write_frame(make_goaway(last_stream_id_, ec));
        co_return false;
      }
      abort_stream(hdr.stream_id);
      co_return co_await write_frame(
          make_rst_stream(hdr.stream_id, h2_error_code::protocol_error));
    }
    if (block_kind == header_block_kind::trailer) {
      st->trailing_headers_received = true;
      if (st->content_length.has_value() &&
          st->req.body.size() != *st->content_length) {
        abort_stream(hdr.stream_id);
        co_return co_await write_frame(
            make_rst_stream(hdr.stream_id, h2_error_code::protocol_error));
      }
    }
    else {
      st->initial_headers_received = true;
    }
    if (st->end_stream) {
      st->state = stream_lifecycle::half_closed_remote;
      co_return start_stream_dispatch(hdr.stream_id);
    }
    co_return true;
  }

  // ── PRIORITY / PUSH_PROMISE ─────────────────────────────────────────────

  async_simple::coro::Lazy<bool> on_priority(
      const frame_header& hdr, std::span<const uint8_t> payload) {
    if (hdr.stream_id == 0) {
      co_await write_frame(
          make_goaway(last_stream_id_, h2_error_code::protocol_error));
      co_return false;
    }
    auto spec = parse_priority_payload(payload);
    if (!spec.has_value()) {
      co_await write_frame(
          make_goaway(last_stream_id_, h2_error_code::frame_size_error));
      co_return false;
    }
    if (spec->stream_dependency == hdr.stream_id) {
      // RFC 7540 §5.3.1: self-dependency is a stream error of type
      // PROTOCOL_ERROR, not a connection error.
      abort_stream(hdr.stream_id);
      co_return co_await write_frame(
          make_rst_stream(hdr.stream_id, h2_error_code::protocol_error));
    }
    co_return true;
  }

  async_simple::coro::Lazy<bool> on_push_promise(
      const frame_header& /*hdr*/, std::span<const uint8_t> /*payload*/) {
    co_await write_frame(
        make_goaway(last_stream_id_, h2_error_code::protocol_error));
    co_return false;
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
    auto st = it->second;
    st->hdr_block_buf.insert(st->hdr_block_buf.end(),
                             payload.begin(), payload.end());
    if (hdr.flags & flags::END_HEADERS) {
      st->end_headers = true;
      pending_continuation_stream_ = 0;
      auto block_kind = st->initial_headers_received ? header_block_kind::trailer
                                                     : header_block_kind::initial;
      auto decode_result = decode_headers(*st, block_kind);
      if (decode_result != header_decode_result::ok) {
        if (decode_result == header_decode_result::connection_error) {
          auto ec = pending_connection_error_.value_or(
              h2_error_code::protocol_error);
          pending_connection_error_.reset();
          co_await write_frame(make_goaway(last_stream_id_, ec));
          co_return false;
        }
        abort_stream(hdr.stream_id);
        co_return co_await write_frame(
            make_rst_stream(hdr.stream_id, h2_error_code::protocol_error));
      }
      if (block_kind == header_block_kind::trailer) {
        st->trailing_headers_received = true;
        if (st->content_length.has_value() &&
            st->req.body.size() != *st->content_length) {
          abort_stream(hdr.stream_id);
          co_return co_await write_frame(
              make_rst_stream(hdr.stream_id, h2_error_code::protocol_error));
        }
      }
      else {
        st->initial_headers_received = true;
      }
      if (st->end_stream) {
        st->state = stream_lifecycle::half_closed_remote;
        co_return start_stream_dispatch(hdr.stream_id);
      }
    }
    co_return true;
  }

  // ── RST_STREAM ───────────────────────────────────────────────────────────

  async_simple::coro::Lazy<bool> on_rst_stream(
      const frame_header& hdr, std::span<const uint8_t> /*payload*/) {
    // RFC 7540 §6.4: RST_STREAM must have stream_id != 0 and payload length 4.
    if (hdr.stream_id == 0) {
      co_await write_frame(
          make_goaway(last_stream_id_, h2_error_code::protocol_error));
      co_return false;
    }
    if (hdr.length != 4) {
      co_await write_frame(
          make_goaway(last_stream_id_, h2_error_code::frame_size_error));
      co_return false;
    }
    // Clean up stream; do not dispatch. (Note: a RST_STREAM arriving while
    // pending_continuation_stream_ != 0 is already rejected by handle_frame,
    // so no continuation reset is needed here.)
    abort_stream(hdr.stream_id);
    co_return true;
  }

  async_simple::coro::Lazy<bool> on_goaway(
      const frame_header& hdr, std::span<const uint8_t> payload) {
    if (hdr.stream_id != 0) {
      co_await write_frame(
          make_goaway(last_stream_id_, h2_error_code::protocol_error));
      co_return false;
    }
    if (payload.size() < 8) {
      co_await write_frame(
          make_goaway(last_stream_id_, h2_error_code::frame_size_error));
      co_return false;
    }

    going_away_ = true;
    peer_sent_goaway_ = true;
    if (streams_.empty()) {
      force_close();
      co_return false;
    }
    co_return true;
  }

  // ── DATA ─────────────────────────────────────────────────────────────────

  async_simple::coro::Lazy<bool> on_data(
      const frame_header& hdr, std::span<const uint8_t> payload) {
    if (hdr.stream_id == 0) {
      co_await write_frame(
          make_goaway(last_stream_id_, h2_error_code::protocol_error));
      co_return false;
    }
    auto it = streams_.find(hdr.stream_id);
    if (it == streams_.end()) {
      co_return co_await write_frame(
          make_rst_stream(hdr.stream_id, h2_error_code::stream_closed));
    }
    auto st = it->second;
    // DATA is only valid in open / half_closed_local (client can still send).
    if (st->state != stream_lifecycle::open &&
        st->state != stream_lifecycle::half_closed_local) {
      co_return co_await write_frame(
          make_rst_stream(hdr.stream_id, h2_error_code::stream_closed));
    }
    payload_view_result data{.ok = true, .payload = payload};
    if (hdr.flags & flags::PADDED) {
      data = strip_padded_payload(payload);
      if (!data.ok) {
        co_await write_frame(make_goaway(last_stream_id_, data.error_code));
        co_return false;
      }
    }
    auto flow_result = co_await consume_flow_control(hdr.stream_id, hdr.length, *st);
    if (flow_result == flow_control_result::connection_error)
      co_return false;
    if (flow_result == flow_control_result::stream_error)
      co_return true;
    st->req.body.append(
        reinterpret_cast<const char*>(data.payload.data()), data.payload.size());
    bool stream_done = (hdr.flags & flags::END_STREAM) != 0;
    if (!co_await refill_flow_control(hdr.stream_id, *st, hdr.length, stream_done))
      co_return false;
    if (hdr.flags & flags::END_STREAM) {
      if (st->content_length.has_value() &&
          st->req.body.size() != *st->content_length) {
        abort_stream(hdr.stream_id);
        co_return co_await write_frame(
            make_rst_stream(hdr.stream_id, h2_error_code::protocol_error));
      }
      st->state = stream_lifecycle::half_closed_remote;
      co_return start_stream_dispatch(hdr.stream_id);
    }
    co_return true;
  }

  // ── PING ─────────────────────────────────────────────────────────────────

  async_simple::coro::Lazy<bool> on_ping(
      const frame_header& hdr, std::span<const uint8_t> payload) {
    if (hdr.stream_id != 0) {
      co_await write_frame(
          make_goaway(last_stream_id_, h2_error_code::protocol_error));
      co_return false;
    }
    if (payload.size() != 8) {
      co_await write_frame(
          make_goaway(last_stream_id_, h2_error_code::frame_size_error));
      co_return false;
    }
    if (hdr.flags & flags::ACK) co_return true;
    std::array<uint8_t, 8> data;
    std::copy_n(payload.begin(), 8, data.begin());
    co_return co_await write_frame(make_ping_ack(data));
  }

  // ── Handler dispatch ─────────────────────────────────────────────────────

  bool start_stream_dispatch(uint32_t stream_id) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) return true;
    auto st = it->second;
    if (st->dispatch_started) return true;
    st->dispatch_started = true;
    if (executor_ == nullptr) return false;

    auto self = shared_from_this();
    [self, stream_id]() -> async_simple::coro::Lazy<void> {
      co_await self->dispatch_stream(stream_id);
    }().via(executor_).detach();
    return true;
  }

  async_simple::coro::Lazy<void> dispatch_stream(uint32_t stream_id) {
    // Look up stream – we hold a shared_ptr, so it stays alive even if
    // the read loop clears the map entry later.
    std::shared_ptr<stream_state> st;
    {
      auto it = streams_.find(stream_id);
      if (it == streams_.end()) co_return;
      st = it->second;
    }

    h2_response resp;
    try {
      co_await handler_(st->req, resp);
    } catch (...) {
      resp.set_status_and_body(500, "Internal Server Error");
    }
    bool ok = co_await send_response(stream_id, *st, resp);
    // Mark for deferred cleanup by the read loop (avoids data race on
    // streams_ map).  The read loop calls cleanup_done_streams() after
    // every frame.
    st->dispatch_done = true;
    pending_cleanup_ = true;
    finish_graceful_shutdown();
    if (!ok && connection_closed_.load()) {
      std::error_code ignored;
      socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ignored);
    }
    co_return;
  }

  // ── Response serialization ───────────────────────────────────────────────

  async_simple::coro::Lazy<bool> send_response(uint32_t stream_id,
                                               stream_state& st,
                                               const h2_response& resp) {
    if (st.state == stream_lifecycle::closed || connection_closed_.load())
      co_return false;

    std::vector<header_field> resp_hdrs;
    resp_hdrs.push_back({":status", std::to_string(resp.status_code)});
    if (!resp.body.empty() && !has_header(resp.headers, "content-length"))
      resp_hdrs.push_back({"content-length", std::to_string(resp.body.size())});
    for (auto& hf : resp.headers) resp_hdrs.push_back(hf);

    uint8_t hdr_flags = flags::END_HEADERS;
    if (resp.body.empty()) hdr_flags |= flags::END_STREAM;

    if (!co_await write_header_block(stream_id, resp_hdrs, hdr_flags)) {
      co_return false;
    }

    if (!resp.body.empty()) {
      st.state = stream_lifecycle::half_closed_local;
      size_t offset = 0;
      while (offset < resp.body.size()) {
        if (st.state == stream_lifecycle::closed || connection_closed_.load())
          co_return false;
        auto chunk = co_await reserve_send_window(st, resp.body.size() - offset);
        if (chunk == 0) co_return false;
        bool last = (offset + chunk == resp.body.size());
        auto span = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(resp.body.data()) + offset, chunk);
        if (!co_await write_frame(make_frame(frame_type::data,
                                             last ? flags::END_STREAM : uint8_t(0),
                                             stream_id, span))) {
          co_return false;
        }
        offset += chunk;
      }
    }
    co_return true;
  }

  async_simple::coro::Lazy<size_t> reserve_send_window(stream_state& st,
                                                       size_t remaining) {
    auto lock = co_await send_window_mutex_.coScopedLock();
    co_await send_window_cv_.wait(send_window_mutex_, [&] {
      return connection_closed_.load() ||
             st.state == stream_lifecycle::closed ||
             (connection_send_window_ > 0 && st.send_window > 0);
    });
    if (connection_closed_.load() || st.state == stream_lifecycle::closed)
      co_return 0;

    auto chunk = std::min<size_t>(
        remaining,
        std::min<uint32_t>(
            std::min<uint32_t>(MAX_FRAME_SIZE, peer_max_frame_size_),
            std::min<uint32_t>(connection_send_window_, st.send_window)));
    connection_send_window_ -= static_cast<int32_t>(chunk);
    st.send_window -= static_cast<int32_t>(chunk);
    co_return chunk;
  }

  // ── Utilities ────────────────────────────────────────────────────────────

  static payload_view_result strip_padded_payload(
      std::span<const uint8_t> payload) {
    uint8_t pad_len = 0;
    if (!payload.empty()) {
      pad_len = payload[0];
      payload = payload.subspan(1);
    }
    if (pad_len > payload.size()) {
      return {.ok = false, .error_code = h2_error_code::protocol_error};
    }
    if (pad_len > 0)
      payload = payload.subspan(0, payload.size() - pad_len);
    return {.ok = true, .payload = payload};
  }

  static payload_view_result strip_padding_priority(
      const frame_header& hdr, std::span<const uint8_t> payload) {
    if (hdr.flags & flags::PADDED) {
      if (payload.empty()) {
        return {.ok = false, .error_code = h2_error_code::protocol_error};
      }
      auto stripped = strip_padded_payload(payload);
      if (!stripped.ok)
        return stripped;
      payload = stripped.payload;
    }
    if (hdr.flags & flags::PRIORITY) {
      if (payload.size() < 5) {
        return {.ok = false, .error_code = h2_error_code::frame_size_error};
      }
      auto spec = parse_priority_payload(payload.first<5>());
      if (!spec.has_value()) {
        return {.ok = false, .error_code = h2_error_code::frame_size_error};
      }
      if (spec->stream_dependency == hdr.stream_id) {
        return {.ok = false,
                .stream_error = true,
                .error_code = h2_error_code::protocol_error};
      }
      payload = payload.subspan(5);
    }
    return {.ok = true, .payload = payload};
  }

  header_decode_result decode_headers(stream_state& st,
                                      header_block_kind block_kind) {
    try {
      auto decoded = decoder_.decode(st.hdr_block_buf);
      st.hdr_block_buf.clear();
      if (!validate_request_headers(decoded, st, block_kind))
        return header_decode_result::stream_error;
      return header_decode_result::ok;
    } catch (...) {
      pending_connection_error_ = h2_error_code::compression_error;
      return header_decode_result::connection_error;
    }
  }

  bool validate_request_headers(std::span<const header_field> decoded,
                                stream_state& st,
                                header_block_kind block_kind) {
    if (block_kind == header_block_kind::trailer) {
      for (auto& hf : decoded) {
        if (contains_invalid_header_name(hf.name) ||
            contains_invalid_header_value(hf.value)) {
          return false;
        }
        if (!hf.name.empty() && hf.name.front() == ':')
          return false;
        if (!validate_request_regular_header(hf.name, hf.value, block_kind))
          return false;
        st.req.trailers.push_back(hf);
      }
      return true;
    }

    bool seen_regular = false;
    bool seen_method = false;
    bool seen_path = false;
    bool seen_scheme = false;
    bool seen_authority = false;
    bool seen_protocol = false;

    st.req = {};
    st.content_length.reset();

    for (auto& hf : decoded) {
      if (contains_invalid_header_name(hf.name) ||
          contains_invalid_header_value(hf.value)) {
        return false;
      }

      bool pseudo = !hf.name.empty() && hf.name.front() == ':';
      if (pseudo) {
        if (seen_regular)
          return false;

        if (hf.name == ":method") {
          if (seen_method) return false;
          seen_method = true;
          st.req.method = hf.value;
        }
        else if (hf.name == ":path") {
          if (seen_path) return false;
          seen_path = true;
          st.req.path = hf.value;
        }
        else if (hf.name == ":scheme") {
          if (seen_scheme) return false;
          seen_scheme = true;
          st.req.scheme = hf.value;
        }
        else if (hf.name == ":authority") {
          if (seen_authority)
            return false;
          seen_authority = true;
          st.req.authority = hf.value;
        }
        else if (hf.name == ":protocol") {
          if (seen_protocol)
            return false;
          seen_protocol = true;
          st.req.protocol = hf.value;
        }
        else {
          return false;
        }
        continue;
      }

      seen_regular = true;
      if (!validate_request_regular_header(hf.name, hf.value, block_kind))
        return false;

      if (hf.name == "content-length") {
        if (st.content_length.has_value())
          return false;
        auto len = parse_content_length(hf.value);
        if (!len.has_value())
          return false;
        st.content_length = *len;
      }
      st.req.headers.push_back(hf);
    }

    if (!seen_method)
      return false;

    bool regular_connect = st.req.method == "CONNECT" && !seen_protocol;
    bool extended_connect = seen_protocol;

    if (extended_connect) {
      if (!enable_connect_protocol_ || st.req.method != "CONNECT" ||
          !seen_scheme || !seen_path || !seen_authority) {
        return false;
      }
    }
    else if (regular_connect) {
      if (seen_scheme || seen_path || !seen_authority) {
        return false;
      }
    }
    else if (!seen_path || !seen_scheme) {
      return false;
    }

    if (seen_path && st.req.path == "*" && st.req.method != "OPTIONS")
      return false;
    if (st.end_stream && st.content_length.has_value() && *st.content_length != 0)
      return false;
    return true;
  }

  async_simple::coro::Lazy<flow_control_result> consume_flow_control(
      uint32_t stream_id, uint32_t amount, stream_state& st) {
    if (amount > static_cast<uint32_t>(connection_recv_window_)) {
      co_await write_frame(
          make_goaway(last_stream_id_, h2_error_code::flow_control_error));
      co_return flow_control_result::connection_error;
    }
    if (amount > static_cast<uint32_t>(st.recv_window)) {
      co_await write_frame(
          make_rst_stream(stream_id, h2_error_code::flow_control_error));
      streams_.erase(stream_id);
      co_return flow_control_result::stream_error;
    }

    connection_recv_window_ -= static_cast<int32_t>(amount);
    st.recv_window -= static_cast<int32_t>(amount);
    co_return flow_control_result::ok;
  }

  // Accumulate consumed bytes and send WINDOW_UPDATE when a threshold is
  // crossed (half of the initial window). Zero-length DATA produces no
  // WINDOW_UPDATE (increment 0 is a protocol error per RFC 7540 §6.9).
  // When stream_done is true (END_STREAM), no stream-level WINDOW_UPDATE
  // is sent since the peer will send no more DATA for this stream.
  async_simple::coro::Lazy<bool> refill_flow_control(
      uint32_t stream_id, stream_state& st, uint32_t amount,
      bool stream_done) {
    if (amount == 0) co_return true;
    connection_recv_pending_ += amount;

    uint32_t threshold = local_initial_window_size_ / 2;
    if (threshold == 0) threshold = 1;
    if (connection_recv_pending_ >= threshold) {
      uint32_t inc = connection_recv_pending_;
      connection_recv_pending_ = 0;
      connection_recv_window_ += static_cast<int32_t>(inc);
      if (!co_await write_frame(make_window_update(0, inc)))
        co_return false;
    }
    if (stream_done) {
      // Peer won't send more on this stream; just absorb locally.
      st.recv_window += static_cast<int32_t>(amount);
      co_return true;
    }
    st.recv_pending += amount;
    if (st.recv_pending >= threshold) {
      uint32_t inc = st.recv_pending;
      st.recv_pending = 0;
      st.recv_window += static_cast<int32_t>(inc);
      if (!co_await write_frame(make_window_update(stream_id, inc)))
        co_return false;
    }
    co_return true;
  }

  void notify_quit() {
    if (quit_callback_) quit_callback_();
  }

  void close_send_waiters() {
    connection_closed_ = true;
    send_window_cv_.notifyAll();
  }

  // Called from the read loop to erase streams that dispatch_stream has
  // finished processing.  This keeps streams_ modifications on the read
  // coroutine, eliminating data races.
  void cleanup_done_streams() {
    if (!pending_cleanup_) return;
    pending_cleanup_ = false;
    for (auto it = streams_.begin(); it != streams_.end();) {
      if (it->second->dispatch_done)
        it = streams_.erase(it);
      else
        ++it;
    }
  }

  void abort_stream(uint32_t stream_id) {
    if (auto it = streams_.find(stream_id); it != streams_.end()) {
      it->second->state = stream_lifecycle::closed;
      streams_.erase(it);
      send_window_cv_.notifyAll();
    }
  }

  bool has_active_streams() const {
    for (auto& [id, st] : streams_) {
      if (!st->dispatch_done) return true;
    }
    return false;
  }

  void finish_graceful_shutdown() {
    if (!going_away_ || connection_closed_.load() || has_active_streams()) return;
    if (peer_sent_goaway_) {
      force_close();
      return;
    }
    close_send_waiters();
    std::error_code ignored;
    socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ignored);
  }

  static bool has_header(std::span<const header_field> headers,
                         std::string_view name) {
    for (auto& hf : headers) {
      if (hf.name == name) return true;
    }
    return false;
  }

  // ── Members ───────────────────────────────────────────────────────────────

  asio::ip::tcp::socket                      socket_;
  h2_handler                                 handler_;
  std::function<void()>                      quit_callback_;
  async_simple::coro::Mutex                  write_mutex_;
  async_simple::coro::Mutex                  header_mutex_;
  async_simple::coro::Mutex                  send_window_mutex_;
  async_simple::coro::ConditionVariable<
      async_simple::coro::Mutex>             send_window_cv_;
  async_simple::Executor*                    executor_ = nullptr;
  hpack_decoder                              decoder_;
  hpack_encoder                              encoder_;
  std::unordered_map<uint32_t, std::shared_ptr<stream_state>> streams_;
  uint32_t                                   last_stream_id_ = 0;
  uint32_t                                   pending_continuation_stream_ = 0;
  uint32_t                                   local_initial_window_size_ =
      DEFAULT_WINDOW_SIZE;
  uint32_t                                   local_max_concurrent_streams_ =
      DEFAULT_MAX_CONCURRENT_STREAMS;
  uint32_t                                   peer_initial_window_size_ =
      DEFAULT_WINDOW_SIZE;
  uint32_t                                   peer_max_frame_size_ =
      MAX_FRAME_SIZE;
  uint32_t                                   peer_max_concurrent_streams_ =
      DEFAULT_MAX_CONCURRENT_STREAMS;
  uint32_t                                   peer_max_header_list_size_ = 0;
  bool                                       peer_enable_connect_protocol_ =
      false;
  bool                                       peer_settings_received_ = false;
  int32_t                                    connection_send_window_ =
      static_cast<int32_t>(DEFAULT_WINDOW_SIZE);
  int32_t                                    connection_recv_window_ =
      static_cast<int32_t>(DEFAULT_WINDOW_SIZE);
  uint32_t                                   connection_recv_pending_ = 0;
  std::atomic<bool>                          connection_closed_ = false;
  bool                                       going_away_ = false;
  bool                                       peer_sent_goaway_ = false;
  bool                                       enable_connect_protocol_ = false;
  bool                                       pending_cleanup_ = false;
  std::optional<h2_error_code>               pending_connection_error_;
  std::vector<uint8_t>                       payload_buf_;
};

}  // namespace cinatra::http2
