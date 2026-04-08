#include <chrono>
#include <iostream>
#include <thread>

#include <asio/io_context.hpp>
#include <async_simple/coro/SyncAwait.h>

#include "cinatra/http2/h2_client.hpp"
#include "cinatra/http2/h2_server.hpp"

using namespace std::chrono_literals;

int main() {
  asio::io_context ioc;
  auto work = asio::make_work_guard(ioc);
  coro_io::ExecutorWrapper<> exec(ioc.get_executor());

  std::thread io_thread([&ioc] { ioc.run(); });

  cinatra::http2::coro_http2_server server(ioc, 0);
  server.set_http_handler<cinatra::GET>(
      "/hello", [](cinatra::http2::h2_request& req,
                    cinatra::http2::h2_response& resp) {
        resp.add_header("content-type", "text/plain");
        resp.set_status_and_body(
            200, req.path == "/hello" ? "hello http2" : "not found");
      });

  auto port = server.start(exec);
  std::this_thread::sleep_for(50ms);

  cinatra::http2::coro_http2_client client(&exec);
  auto ec = async_simple::coro::syncAwait(
      client.connect("127.0.0.1", std::to_string(port)));
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
}
