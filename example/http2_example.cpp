#include <chrono>
#include <iostream>
#include <thread>

#include <asio/io_context.hpp>
#include <async_simple/coro/SyncAwait.h>

#include "cinatra/coro_http_server.hpp"
#include "cinatra/http2/h2_client.hpp"

using namespace std::chrono_literals;

int main() {
#ifndef CINATRA_ENABLE_SSL
  std::cerr << "http2_example requires CINATRA_ENABLE_SSL\n";
  return 1;
#else
  asio::io_context ioc;
  auto work = asio::make_work_guard(ioc);
  coro_io::ExecutorWrapper<> exec(ioc.get_executor());

  std::thread io_thread([&ioc] { ioc.run(); });

  cinatra::coro_http_server server(ioc, 0);
  server.set_http2_mode(cinatra::http2_mode::required);
  server.init_ssl("include/cinatra/server.crt", "include/cinatra/server.key",
                  "test");
  server.set_http_handler<cinatra::GET>(
      "/hello", [](cinatra::coro_http_request& req,
                    cinatra::coro_http_response& resp) {
        resp.add_header("content-type", "text/plain");
        resp.set_status_and_content(
            cinatra::status_type::ok,
            req.get_url() == "/hello" ? "hello http2" : "not found");
      });

  server.async_start();
  auto port = server.port();
  std::this_thread::sleep_for(50ms);

  cinatra::http2::coro_http2_client client(&exec);
  auto ec = async_simple::coro::syncAwait(
      client.connect("127.0.0.1", std::to_string(port), "https"));
  if (ec) {
    std::cerr << "connect failed: " << ec.message() << '\n';
    server.stop();
    work.reset();
    ioc.stop();
    io_thread.join();
    return 1;
  }

  auto resp = async_simple::coro::syncAwait(client.async_get("/hello"));
  if (resp.net_err) {
    std::cerr << "request failed: " << resp.net_err.message() << '\n';
    client.close();
    server.stop();
    work.reset();
    ioc.stop();
    io_thread.join();
    return 1;
  }

  std::cout << "status: " << resp.status_code << '\n';
  std::cout << "body: " << resp.body << '\n';

  client.close();
  server.stop();
  work.reset();
  ioc.stop();
  io_thread.join();
  return 0;
#endif
}
