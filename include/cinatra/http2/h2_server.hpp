#pragma once
#include <async_simple/coro/Lazy.h>

#include <asio/ip/tcp.hpp>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>

#include "cinatra/define.h"
#include "cinatra/ylt/coro_io/coro_io.hpp"
#include "connection.hpp"

// HTTP/2 router and server – Phase 1
// Router: exact-match only (radix tree / regex in Phase 2).
// Server: accept loop that dispatches each stream through the router.
namespace cinatra::http2 {

// ── H2 Router ────────────────────────────────────────────────────────────────
// Route key format: "METHOD /path"  (same convention as coro_http_router)

class h2_router {
 public:
  // Register a handler for one or more HTTP methods.
  // Func may be sync (void) or coroutine (Lazy<void>).
  template <http_method... methods, typename Func>
  void set_http_handler(std::string path, Func handler) {
    (register_one<methods>(path, handler), ...);
  }

  // Set a catch-all handler for unmatched requests.
  void set_default_handler(h2_handler handler) {
    default_handler_ = std::move(handler);
  }

  // Dispatch req/resp to the matching handler.
  async_simple::coro::Lazy<void> dispatch(h2_request& req,
                                           h2_response& resp) const {
    std::string key;
    key.reserve(req.method.size() + 1 + req.path.size());
    key.append(req.method).append(" ").append(req.path);

    if (auto it = handlers_.find(key); it != handlers_.end()) {
      co_await invoke_safe(it->second, req, resp);
      co_return;
    }

    if (default_handler_) {
      co_await invoke_safe(default_handler_, req, resp);
      co_return;
    }

    resp.set_status_and_body(404, "Not Found");
  }

 private:
  template <http_method M, typename Func>
  void register_one(const std::string& path, Func& fn) {
    std::string key;
    key.append(method_name(M)).append(" ").append(path);

    using ret_t =
        std::invoke_result_t<std::decay_t<Func>, h2_request&, h2_response&>;

    h2_handler h;
    if constexpr (coro_io::is_lazy_v<ret_t>) {
      h = fn;
    } else {
      h = [fn](h2_request& req, h2_response& resp)
              -> async_simple::coro::Lazy<void> {
        fn(req, resp);
        co_return;
      };
    }

    auto [it, ok] = keys_.emplace(std::move(key));
    if (!ok) return;  // already registered
    handlers_.emplace(*it, std::move(h));
  }

  static async_simple::coro::Lazy<void> invoke_safe(const h2_handler& h,
                                                      h2_request& req,
                                                      h2_response& resp) {
    try {
      co_await h(req, resp);
    } catch (const std::exception& e) {
      resp.set_status_and_body(500, e.what());
    } catch (...) {
      resp.set_status_and_body(500, "Internal Server Error");
    }
  }

  std::set<std::string> keys_;
  std::unordered_map<std::string_view, h2_handler> handlers_;
  h2_handler default_handler_;
};

// ── H2 Server ─────────────────────────────────────────────────────────────────
// Usage:
//   coro_http2_server srv(ioc, 0 /*port*/);
//   srv.set_http_handler<GET>("/hello", [](h2_request& req, h2_response& resp) {
//       resp.set_status_and_body(200, "hello");
//   });
//   uint16_t port = srv.start(*exec);
//   // ioc.run() drives everything

class coro_http2_server {
 public:
  coro_http2_server(asio::io_context& ioc, uint16_t port)
      : ioc_(&ioc),
        acceptor_(ioc, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)) {
    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
  }

  // Register handler for one or more HTTP methods.
  template <http_method... methods, typename Func>
  void set_http_handler(std::string path, Func handler) {
    router_.set_http_handler<methods...>(std::move(path), std::move(handler));
  }

  void set_default_handler(h2_handler handler) {
    router_.set_default_handler(std::move(handler));
  }

  // Start the accept loop on exec.  Returns the bound port (useful when 0 was
  // passed to the constructor).
  uint16_t start(coro_io::ExecutorWrapper<>& exec) {
    uint16_t p = acceptor_.local_endpoint().port();
    accept_loop(exec).via(&exec).detach();
    return p;
  }

  uint16_t port() const { return acceptor_.local_endpoint().port(); }

 private:
  async_simple::coro::Lazy<void> accept_loop(
      coro_io::ExecutorWrapper<>& exec) {
    while (true) {
      asio::ip::tcp::socket sock(*ioc_);
      auto ec = co_await coro_io::async_accept(acceptor_, sock);
      if (ec) co_return;

      // Capture router by pointer (server outlives connections).
      auto* rp = &router_;
      auto conn = std::make_shared<coro_http2_connection>(
          std::move(sock),
          [rp](h2_request& req, h2_response& resp)
              -> async_simple::coro::Lazy<void> {
            co_await rp->dispatch(req, resp);
          });
      // Capture conn by value so the shared_ptr keeps the connection alive
      // until start() completes (detached Lazy owns the coroutine frame which
      // holds conn).
      [conn]() -> async_simple::coro::Lazy<void> {
        co_await conn->start();
      }().via(&exec).detach();
    }
  }

  asio::io_context* ioc_;
  asio::ip::tcp::acceptor acceptor_;
  h2_router router_;
};

}  // namespace cinatra::http2
