#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest/doctest.h"

#include <array>
#include <string>
#include <thread>
#include <vector>

#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/write.hpp>
#include <asio/read.hpp>
#include <async_simple/coro/SyncAwait.h>

#include "cinatra/http2/frame.hpp"
#include "cinatra/http2/hpack.hpp"
#include "cinatra/http2/connection.hpp"
#include "cinatra/http2/h2_server.hpp"

using namespace cinatra::http2;

// ════════════════════════════════════════════════════════════════════════════
// Frame tests
// ════════════════════════════════════════════════════════════════════════════

TEST_CASE("frame header roundtrip") {
  frame_header orig{
      .length    = 0x123456,
      .type      = frame_type::headers,
      .flags     = flags::END_HEADERS | flags::END_STREAM,
      .stream_id = 0x7FFFFFFF,
  };
  auto bytes = serialize_frame_header(orig);
  CHECK(bytes.size() == 9);

  auto parsed = parse_frame_header(bytes);
  CHECK(parsed.length    == orig.length);
  CHECK(parsed.type      == orig.type);
  CHECK(parsed.flags     == orig.flags);
  CHECK(parsed.stream_id == orig.stream_id);
}

TEST_CASE("frame header R-bit is masked") {
  // Bit 31 of stream_id is reserved and must be ignored on receive
  frame_header h{.length = 0, .type = frame_type::data,
                 .flags = 0, .stream_id = 1};
  auto bytes = serialize_frame_header(h);
  // Force R-bit on in raw bytes
  bytes[5] |= 0x80;
  auto parsed = parse_frame_header(bytes);
  CHECK(parsed.stream_id == 1);  // R-bit masked out
}

TEST_CASE("make_frame produces correct bytes") {
  std::vector<uint8_t> payload{0xDE, 0xAD, 0xBE, 0xEF};
  auto frame = make_frame(frame_type::data, flags::END_STREAM, 1, payload);

  CHECK(frame.size() == 9 + 4);
  // Length = 4
  CHECK((uint8_t)frame[0] == 0);
  CHECK((uint8_t)frame[1] == 0);
  CHECK((uint8_t)frame[2] == 4);
  // Type = DATA
  CHECK((uint8_t)frame[3] == 0x0);
  // Flags = END_STREAM
  CHECK((uint8_t)frame[4] == flags::END_STREAM);
  // Stream id = 1
  CHECK((uint8_t)frame[8] == 1);
  // Payload
  CHECK((uint8_t)frame[9]  == 0xDE);
  CHECK((uint8_t)frame[12] == 0xEF);
}

TEST_CASE("SETTINGS frame build and parse") {
  std::array<settings_entry, 2> entries{
      settings_entry{settings_param::max_frame_size,      65535},
      settings_entry{settings_param::initial_window_size, 131072},
  };
  auto frame = make_settings_frame(entries);

  // Frame header checks
  auto hdr = parse_frame_header(
      std::span<const uint8_t, 9>(
          reinterpret_cast<const uint8_t*>(frame.data()), 9));
  CHECK(hdr.type      == frame_type::settings);
  CHECK(hdr.flags     == 0);
  CHECK(hdr.stream_id == 0);
  CHECK(hdr.length    == 12);  // 2 entries × 6 bytes

  // Payload parsing
  auto payload = std::span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(frame.data()) + 9, hdr.length);
  auto parsed = parse_settings_payload(payload);
  REQUIRE(parsed.size() == 2);
  CHECK(parsed[0].id    == settings_param::max_frame_size);
  CHECK(parsed[0].value == 65535);
  CHECK(parsed[1].id    == settings_param::initial_window_size);
  CHECK(parsed[1].value == 131072);
}

TEST_CASE("SETTINGS ACK is empty with ACK flag") {
  auto frame = make_settings_frame({}, true);
  auto hdr = parse_frame_header(
      std::span<const uint8_t, 9>(
          reinterpret_cast<const uint8_t*>(frame.data()), 9));
  CHECK(hdr.length == 0);
  CHECK(hdr.flags  == flags::ACK);
}

TEST_CASE("make_rst_stream") {
  auto frame = make_rst_stream(5, h2_error_code::cancel);
  auto hdr = parse_frame_header(
      std::span<const uint8_t, 9>(
          reinterpret_cast<const uint8_t*>(frame.data()), 9));
  CHECK(hdr.type      == frame_type::rst_stream);
  CHECK(hdr.stream_id == 5);
  CHECK(hdr.length    == 4);
  auto* p = reinterpret_cast<const uint8_t*>(frame.data()) + 9;
  uint32_t code = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
                | (uint32_t(p[2]) << 8)  |  uint32_t(p[3]);
  CHECK(code == uint32_t(h2_error_code::cancel));
}

TEST_CASE("CLIENT_PREFACE is 24 bytes") {
  CHECK(CLIENT_PREFACE.size() == 24);
  CHECK(CLIENT_PREFACE.substr(0, 3) == "PRI");
}

// ════════════════════════════════════════════════════════════════════════════
// HPACK tests
// ════════════════════════════════════════════════════════════════════════════

TEST_CASE("hpack decode: indexed field from static table") {
  // Index 2 = :method GET  (0x82 = 0b10000010)
  std::array<uint8_t, 1> block{0x82};
  hpack_decoder dec;
  auto hdrs = dec.decode(block);
  REQUIRE(hdrs.size() == 1);
  CHECK(hdrs[0].name  == ":method");
  CHECK(hdrs[0].value == "GET");
}

TEST_CASE("hpack decode: multiple static indexed fields") {
  // 0x82 = :method GET, 0x84 = :path /, 0x87 = :scheme https
  std::array<uint8_t, 3> block{0x82, 0x84, 0x87};
  hpack_decoder dec;
  auto hdrs = dec.decode(block);
  REQUIRE(hdrs.size() == 3);
  CHECK(hdrs[0].name  == ":method"); CHECK(hdrs[0].value == "GET");
  CHECK(hdrs[1].name  == ":path");   CHECK(hdrs[1].value == "/");
  CHECK(hdrs[2].name  == ":scheme"); CHECK(hdrs[2].value == "https");
}

TEST_CASE("hpack decode: literal with incremental indexing, new name+value") {
  // 0x40 = literal with incremental indexing, index=0 (new name)
  // name  = "x-custom"  (length 8, no huffman)
  // value = "hello"     (length 5, no huffman)
  std::vector<uint8_t> block;
  block.push_back(0x40);           // literal, incremental, new name
  block.push_back(0x08);           // name length = 8
  for (char c : std::string("x-custom")) block.push_back(uint8_t(c));
  block.push_back(0x05);           // value length = 5
  for (char c : std::string("hello")) block.push_back(uint8_t(c));

  hpack_decoder dec;
  auto hdrs = dec.decode(block);
  REQUIRE(hdrs.size() == 1);
  CHECK(hdrs[0].name  == "x-custom");
  CHECK(hdrs[0].value == "hello");
}

TEST_CASE("hpack decode: literal incremental indexing, indexed name") {
  // 0x5C = 0b01011100 = literal incr. indexing, name index 28 (:content-length)
  // Actually index 28 is "content-length"
  // 0x40 | 28 = 0x5C
  std::vector<uint8_t> block;
  block.push_back(0x40 | 28);  // literal incr., name = static[28] = content-length
  block.push_back(0x02);       // value length = 2
  block.push_back('4');
  block.push_back('2');

  hpack_decoder dec;
  auto hdrs = dec.decode(block);
  REQUIRE(hdrs.size() == 1);
  CHECK(hdrs[0].name  == "content-length");
  CHECK(hdrs[0].value == "42");
}

TEST_CASE("hpack decode: literal without indexing") {
  // 0x00 = literal without indexing, index=0 (new name)
  std::vector<uint8_t> block;
  block.push_back(0x00);  // no indexing, new name
  block.push_back(0x04);
  for (char c : std::string("host")) block.push_back(uint8_t(c));
  block.push_back(0x09);
  for (char c : std::string("localhost")) block.push_back(uint8_t(c));

  hpack_decoder dec;
  auto hdrs = dec.decode(block);
  REQUIRE(hdrs.size() == 1);
  CHECK(hdrs[0].name  == "host");
  CHECK(hdrs[0].value == "localhost");
}

TEST_CASE("hpack dynamic table is populated by incremental indexing") {
  hpack_decoder dec;
  // First add "x-foo: bar" via literal with incremental indexing
  std::vector<uint8_t> block;
  block.push_back(0x40);
  block.push_back(0x05);
  for (char c : std::string("x-foo")) block.push_back(uint8_t(c));
  block.push_back(0x03);
  for (char c : std::string("bar")) block.push_back(uint8_t(c));

  auto hdrs = dec.decode(block);
  REQUIRE(hdrs.size() == 1);
  CHECK(hdrs[0].name == "x-foo");

  // Now reference it via dynamic table index = 62
  std::array<uint8_t, 1> block2{0x80 | 62};  // indexed, index 62
  auto hdrs2 = dec.decode(block2);
  REQUIRE(hdrs2.size() == 1);
  CHECK(hdrs2[0].name  == "x-foo");
  CHECK(hdrs2[0].value == "bar");
}

TEST_CASE("hpack integer encoding: single byte") {
  std::vector<uint8_t> out;
  encode_integer(out, 10, 5, 0);
  REQUIRE(out.size() == 1);
  CHECK(out[0] == 10);
}

TEST_CASE("hpack integer encoding: multi-byte") {
  // Encode 1337 with 5-bit prefix (RFC 7541 §C.1.2 example)
  std::vector<uint8_t> out;
  encode_integer(out, 1337, 5, 0);
  REQUIRE(out.size() == 3);
  CHECK(out[0] == 31);   // 2^5 - 1 = prefix exhausted
  CHECK(out[1] == 154);  // (1337 - 31) & 0x7f | 0x80
  CHECK(out[2] == 10);   // remainder
}

TEST_CASE("hpack integer decode roundtrip") {
  for (uint32_t val : {0u, 1u, 30u, 31u, 127u, 128u, 255u, 1337u, 65535u}) {
    std::vector<uint8_t> encoded;
    encode_integer(encoded, val, 5, 0);
    std::span<const uint8_t> sp(encoded);
    uint32_t decoded = decode_integer(sp, 5);
    CHECK(decoded == val);
    CHECK(sp.empty());
  }
}

TEST_CASE("hpack encode + decode roundtrip") {
  std::vector<header_field> input{
      {":method",    "GET"},
      {":path",      "/hello"},
      {":scheme",    "https"},
      {":authority", "example.com"},
      {"user-agent", "test/1.0"},
  };

  hpack_encoder enc;
  auto block = enc.encode(input);

  hpack_decoder dec;
  auto output = dec.decode(block);

  REQUIRE(output.size() == input.size());
  for (size_t i = 0; i < input.size(); ++i) {
    CHECK(output[i].name  == input[i].name);
    CHECK(output[i].value == input[i].value);
  }
}

TEST_CASE("hpack encoder uses static table indexed form") {
  hpack_encoder enc;
  // :method GET = static index 2 → should encode as single byte 0x82
  std::vector<header_field> input{{":method", "GET"}};
  auto block = enc.encode(input);
  REQUIRE(block.size() == 1);
  CHECK(block[0] == 0x82);
}

TEST_CASE("hpack encoder uses indexed name from static table") {
  hpack_encoder enc;
  // :method has static index 2 (GET) but value is POST = static index 3
  std::vector<header_field> input{{":method", "POST"}};
  auto block = enc.encode(input);
  REQUIRE(block.size() == 1);
  CHECK(block[0] == 0x83);  // index 3 = :method POST
}

// ════════════════════════════════════════════════════════════════════════════
// Integration test helpers
// ════════════════════════════════════════════════════════════════════════════

// Server runner: ioc_thread drives ASIO; conn_thread runs the connection
// coroutine via syncAwait (blocks until the connection closes).
struct server_runner {
  asio::io_context ioc;
  asio::executor_work_guard<asio::io_context::executor_type> work{
      asio::make_work_guard(ioc)};
  std::thread ioc_thread;
  std::thread conn_thread;

  server_runner() : ioc_thread([this] { ioc.run(); }) {}

  void launch(h2_handler handler) {
    auto acc = std::make_shared<asio::ip::tcp::acceptor>(
        ioc, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    acc->set_option(asio::ip::tcp::acceptor::reuse_address(true));
    port_ = acc->local_endpoint().port();

    auto h = std::make_shared<h2_handler>(std::move(handler));

    // conn_thread runs syncAwait: blocks until one connection is served.
    // ioc_thread drives all ASIO callbacks, resuming the coroutine as I/O
    // completes.
    conn_thread = std::thread([acc, h, this]() {
      async_simple::coro::syncAwait(
          [acc, h, this]() -> async_simple::coro::Lazy<void> {
            asio::ip::tcp::socket sock(ioc);
            auto ec = co_await coro_io::async_accept(*acc, sock);
            if (ec) co_return;
            auto conn = std::make_shared<coro_http2_connection>(
                std::move(sock), std::move(*h));
            co_await conn->start();
          }());
    });
  }

  uint16_t port() const { return port_; }

  void stop() {
    work.reset();
    // Join ioc_thread first: it processes pending I/O that unblocks conn_thread.
    if (ioc_thread.joinable()) ioc_thread.join();
    if (conn_thread.joinable()) conn_thread.join();
  }
  ~server_runner() { stop(); }

 private:
  uint16_t port_ = 0;
};

// RAII wrapper: starts io_context on a background thread.
// exec lives as long as the runner (safe for via() pointer).
struct ioc_runner {
  asio::io_context ioc;
  std::unique_ptr<coro_io::ExecutorWrapper<>> exec;
  asio::executor_work_guard<asio::io_context::executor_type> work{
      asio::make_work_guard(ioc)};
  std::thread thread{[this] { ioc.run(); }};

  ioc_runner()
      : exec(std::make_unique<coro_io::ExecutorWrapper<>>(ioc.get_executor())) {}

  void stop() {
    work.reset();
    if (thread.joinable()) thread.join();
  }

  ~ioc_runner() { stop(); }
};

// Build minimal HTTP/2 GET request bytes:
//   client preface + SETTINGS + HEADERS(END_HEADERS|END_STREAM)
static std::string build_get_frames(const std::string& path) {
  std::string frames(CLIENT_PREFACE);
  frames += make_settings_frame({});

  hpack_encoder enc;
  std::vector<header_field> hdrs{
      {":method", "GET"}, {":path", path},
      {":scheme", "http"}, {":authority", "localhost"},
  };
  auto block = enc.encode(hdrs);
  frames += make_frame(frame_type::headers,
                        flags::END_HEADERS | flags::END_STREAM, 1,
                        std::span<const uint8_t>(block));
  return frames;
}

// Read frames from a blocking socket until END_STREAM.
// Sends SETTINGS ACK automatically. Returns {status, body}.
static std::pair<int, std::string> read_h2_response(
    asio::ip::tcp::socket& sock) {
  std::array<uint8_t, 9> hdr_buf;
  std::vector<uint8_t> payload;
  std::string body;
  int status = 0;
  hpack_decoder dec;

  for (;;) {
    std::error_code ec;
    asio::read(sock, asio::buffer(hdr_buf), ec);
    if (ec) break;

    auto hdr = parse_frame_header(hdr_buf);
    payload.resize(hdr.length);
    if (hdr.length > 0) {
      asio::read(sock, asio::buffer(payload), ec);
      if (ec) break;
    }

    if (hdr.type == frame_type::settings && !(hdr.flags & flags::ACK)) {
      auto ack = make_settings_frame({}, true);
      asio::write(sock, asio::buffer(ack), ec);
    } else if (hdr.type == frame_type::headers) {
      auto decoded = dec.decode(std::span<const uint8_t>(payload));
      for (auto& h : decoded)
        if (h.name == ":status") status = std::stoi(h.value);
      if (hdr.flags & flags::END_STREAM) break;
    } else if (hdr.type == frame_type::data) {
      body.append(reinterpret_cast<const char*>(payload.data()),
                  payload.size());
      if (hdr.flags & flags::END_STREAM) break;
    }
  }
  return {status, body};
}

// Launch a coro_http2_connection on `runner` and return its port.
// All I/O (accept + serve) runs on runner.ioc via via(exec).detach().
static uint16_t start_h2_server(ioc_runner& runner, h2_handler handler) {
  auto acc = std::make_shared<asio::ip::tcp::acceptor>(
      runner.ioc, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
  acc->set_option(asio::ip::tcp::acceptor::reuse_address(true));
  uint16_t port = acc->local_endpoint().port();

  auto h = std::make_shared<h2_handler>(std::move(handler));

  // Schedule the accept+serve coroutine on runner's executor.
  // via(exec).detach() dispatches to ioc so IOCP callbacks drive it correctly.
  [acc, h, &runner]() -> async_simple::coro::Lazy<void> {
    asio::ip::tcp::socket sock(runner.ioc);
    auto ec = co_await coro_io::async_accept(*acc, sock);
    if (ec) co_return;
    auto conn = std::make_shared<coro_http2_connection>(
        std::move(sock), std::move(*h));
    co_await conn->start();
  }().via(runner.exec.get()).detach();

  return port;
}

// ════════════════════════════════════════════════════════════════════════════
// Integration tests
// ════════════════════════════════════════════════════════════════════════════

TEST_CASE("integration: HTTP/2 GET returns 200 with body") {
  server_runner srv;
  srv.launch([](h2_request& req, h2_response& resp)
                 -> async_simple::coro::Lazy<void> {
    resp.set_status_and_body(req.path == "/hello" ? 200 : 404,
                              req.path == "/hello" ? "hello http2" : "not found");
    co_return;
  });
  uint16_t port = srv.port();

  // Client uses a separate blocking io_context (no async needed)
  asio::io_context client_ioc;
  asio::ip::tcp::socket client(client_ioc);
  client.connect(asio::ip::tcp::endpoint(
      asio::ip::address::from_string("127.0.0.1"), port));

  asio::write(client, asio::buffer(build_get_frames("/hello")));
  auto [status, body] = read_h2_response(client);

  CHECK(status == 200);
  CHECK(body   == "hello http2");
  client.close();
}

TEST_CASE("integration: unknown path returns 404") {
  server_runner srv;
  srv.launch([](h2_request& req, h2_response& resp)
                 -> async_simple::coro::Lazy<void> {
    resp.set_status_and_body(req.path == "/exists" ? 200 : 404, "not found");
    co_return;
  });
  uint16_t port = srv.port();

  asio::io_context client_ioc;
  asio::ip::tcp::socket client(client_ioc);
  client.connect(asio::ip::tcp::endpoint(
      asio::ip::address::from_string("127.0.0.1"), port));

  asio::write(client, asio::buffer(build_get_frames("/missing")));
  auto [status, body] = read_h2_response(client);
  CHECK(status == 404);
  client.close();
}

TEST_CASE("integration: PING is answered with ACK") {
  server_runner srv;
  srv.launch([](h2_request&, h2_response& resp)
                 -> async_simple::coro::Lazy<void> {
    resp.set_status_and_body(200, "");
    co_return;
  });
  uint16_t port = srv.port();

  asio::io_context client_ioc;
  asio::ip::tcp::socket client(client_ioc);
  client.connect(asio::ip::tcp::endpoint(
      asio::ip::address::from_string("127.0.0.1"), port));

  // Send preface + SETTINGS + PING
  std::string init(CLIENT_PREFACE);
  init += make_settings_frame({});
  asio::write(client, asio::buffer(init));

  std::array<uint8_t, 8> ping_data{1, 2, 3, 4, 5, 6, 7, 8};
  asio::write(client, asio::buffer(
      make_frame(frame_type::ping, 0, 0, ping_data)));

  // Scan frames for PING ACK
  bool got_ack = false;
  std::array<uint8_t, 9> hdr_buf;
  std::vector<uint8_t> payload;
  for (int i = 0; i < 10 && !got_ack; ++i) {
    std::error_code ec;
    asio::read(client, asio::buffer(hdr_buf), ec);
    if (ec) break;
    auto hdr = parse_frame_header(hdr_buf);
    payload.resize(hdr.length);
    if (hdr.length > 0) asio::read(client, asio::buffer(payload));

    if (hdr.type == frame_type::settings && !(hdr.flags & flags::ACK)) {
      asio::write(client, asio::buffer(make_settings_frame({}, true)));
    } else if (hdr.type == frame_type::ping && (hdr.flags & flags::ACK)) {
      CHECK(payload == std::vector<uint8_t>(ping_data.begin(), ping_data.end()));
      got_ack = true;
    }
  }
  CHECK(got_ack);
  client.close();
}

// ════════════════════════════════════════════════════════════════════════════
// h2_router unit tests
// ════════════════════════════════════════════════════════════════════════════

TEST_CASE("h2_router: dispatch to exact-match GET handler") {
  h2_router router;
  router.set_http_handler<cinatra::GET>("/hello",
      [](h2_request& req, h2_response& resp) {
        resp.set_status_and_body(200, "hello");
      });

  h2_request req;  req.method = "GET";  req.path = "/hello";
  h2_response resp;
  async_simple::coro::syncAwait(router.dispatch(req, resp));

  CHECK(resp.status_code == 200);
  CHECK(resp.body == "hello");
}

TEST_CASE("h2_router: 404 for unregistered path") {
  h2_router router;
  router.set_http_handler<cinatra::GET>("/exists",
      [](h2_request&, h2_response& resp) {
        resp.set_status_and_body(200, "ok");
      });

  h2_request req;  req.method = "GET";  req.path = "/missing";
  h2_response resp;
  async_simple::coro::syncAwait(router.dispatch(req, resp));

  CHECK(resp.status_code == 404);
}

TEST_CASE("h2_router: method mismatch returns 404") {
  h2_router router;
  router.set_http_handler<cinatra::POST>("/data",
      [](h2_request&, h2_response& resp) {
        resp.set_status_and_body(200, "posted");
      });

  h2_request req;  req.method = "GET";  req.path = "/data";
  h2_response resp;
  async_simple::coro::syncAwait(router.dispatch(req, resp));

  CHECK(resp.status_code == 404);
}

TEST_CASE("h2_router: multi-method registration") {
  h2_router router;
  router.set_http_handler<cinatra::GET, cinatra::POST>("/multi",
      [](h2_request& req, h2_response& resp) {
        resp.set_status_and_body(200, req.method);
      });

  for (auto m : {"GET", "POST"}) {
    h2_request req;  req.method = m;  req.path = "/multi";
    h2_response resp;
    async_simple::coro::syncAwait(router.dispatch(req, resp));
    CHECK(resp.status_code == 200);
    CHECK(resp.body == m);
  }
}

TEST_CASE("h2_router: default handler fires for unmatched routes") {
  h2_router router;
  router.set_default_handler(
      [](h2_request& req, h2_response& resp)
          -> async_simple::coro::Lazy<void> {
        resp.set_status_and_body(418, "teapot");
        co_return;
      });

  h2_request req;  req.method = "GET";  req.path = "/anything";
  h2_response resp;
  async_simple::coro::syncAwait(router.dispatch(req, resp));

  CHECK(resp.status_code == 418);
  CHECK(resp.body == "teapot");
}

TEST_CASE("h2_router: coroutine handler is supported") {
  h2_router router;
  router.set_http_handler<cinatra::GET>("/coro",
      [](h2_request&, h2_response& resp)
          -> async_simple::coro::Lazy<void> {
        resp.set_status_and_body(200, "coro ok");
        co_return;
      });

  h2_request req;  req.method = "GET";  req.path = "/coro";
  h2_response resp;
  async_simple::coro::syncAwait(router.dispatch(req, resp));

  CHECK(resp.status_code == 200);
  CHECK(resp.body == "coro ok");
}

TEST_CASE("h2_router: handler exception returns 500") {
  h2_router router;
  router.set_http_handler<cinatra::GET>("/boom",
      [](h2_request&, h2_response&) {
        throw std::runtime_error("oops");
      });

  h2_request req;  req.method = "GET";  req.path = "/boom";
  h2_response resp;
  async_simple::coro::syncAwait(router.dispatch(req, resp));

  CHECK(resp.status_code == 500);
}

// ════════════════════════════════════════════════════════════════════════════
// coro_http2_server integration tests
// ════════════════════════════════════════════════════════════════════════════

TEST_CASE("coro_http2_server: GET /hello returns 200") {
  ioc_runner runner;
  coro_http2_server srv(runner.ioc, 0);
  srv.set_http_handler<cinatra::GET>("/hello",
      [](h2_request&, h2_response& resp) {
        resp.set_status_and_body(200, "hello from server");
      });
  uint16_t port = srv.start(*runner.exec);

  asio::io_context client_ioc;
  asio::ip::tcp::socket client(client_ioc);
  client.connect(asio::ip::tcp::endpoint(
      asio::ip::address::from_string("127.0.0.1"), port));

  asio::write(client, asio::buffer(build_get_frames("/hello")));
  auto [status, body] = read_h2_response(client);

  CHECK(status == 200);
  CHECK(body == "hello from server");
  client.close();
}

TEST_CASE("coro_http2_server: unknown route returns 404") {
  ioc_runner runner;
  coro_http2_server srv(runner.ioc, 0);
  srv.set_http_handler<cinatra::GET>("/only",
      [](h2_request&, h2_response& resp) {
        resp.set_status_and_body(200, "ok");
      });
  uint16_t port = srv.start(*runner.exec);

  asio::io_context client_ioc;
  asio::ip::tcp::socket client(client_ioc);
  client.connect(asio::ip::tcp::endpoint(
      asio::ip::address::from_string("127.0.0.1"), port));

  asio::write(client, asio::buffer(build_get_frames("/other")));
  auto [status, body] = read_h2_response(client);

  CHECK(status == 404);
  client.close();
}

TEST_CASE("coro_http2_server: multiple routes dispatch correctly") {
  ioc_runner runner;
  coro_http2_server srv(runner.ioc, 0);
  srv.set_http_handler<cinatra::GET>("/a",
      [](h2_request&, h2_response& resp) {
        resp.set_status_and_body(200, "route-a");
      });
  srv.set_http_handler<cinatra::GET>("/b",
      [](h2_request&, h2_response& resp) {
        resp.set_status_and_body(200, "route-b");
      });
  uint16_t port = srv.start(*runner.exec);

  for (auto [path, expected] :
       std::initializer_list<std::pair<const char*, const char*>>{
           {"/a", "route-a"}, {"/b", "route-b"}}) {
    asio::io_context clioc;
    asio::ip::tcp::socket client(clioc);
    client.connect(asio::ip::tcp::endpoint(
        asio::ip::address::from_string("127.0.0.1"), port));
    asio::write(client, asio::buffer(build_get_frames(path)));
    auto [status, body] = read_h2_response(client);
    CHECK(status == 200);
    CHECK(body == expected);
    client.close();
  }
}
