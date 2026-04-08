#pragma once
#include <async_simple/coro/Lazy.h>

#include <asio/ip/tcp.hpp>
#include <functional>
#include <memory>
#include <mutex>
#include <regex>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>

#include "cinatra/define.h"
#include "cinatra/ylt/coro_io/coro_io.hpp"
#include "connection.hpp"

// HTTP/2 router and server – Phase 2
// Router: exact match + parameterized paths + regex paths.
// Server: accept loop keeps accepting while each connection runs independently.
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
    req.params_.clear();
    req.matches_ = std::smatch{};

    std::string key;
    key.reserve(req.method.size() + 1 + req.path.size());
    key.append(req.method).append(" ").append(req.path);

    if (auto it = handlers_.find(key); it != handlers_.end()) {
      co_await invoke_safe(it->second, req, resp);
      co_return;
    }

    for (auto& route : param_routes_) {
      req.params_.clear();
      if (route.method == req.method &&
          match_param_route(route.path, req.path, req.params_)) {
        co_await invoke_safe(route.handler, req, resp);
        co_return;
      }
    }

    for (auto& route : regex_routes_) {
      std::string regex_key = key;
      if (std::regex_match(regex_key, req.matches_, route.pattern)) {
        co_await invoke_safe(route.handler, req, resp);
        co_return;
      }
    }

    if (default_handler_) {
      co_await invoke_safe(default_handler_, req, resp);
      co_return;
    }

    resp.set_status_and_body(404, "Not Found");
  }

 private:
  struct param_route {
    std::string method;
    std::string path;
    h2_handler  handler;
  };

  struct regex_route {
    std::regex pattern;
    h2_handler handler;
  };

  template <http_method M, typename Func>
  void register_one(const std::string& path, Func& fn) {
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

    std::string method(method_name(M));
    if (path.find(':') != std::string::npos ||
        path.find('*') != std::string::npos) {
      param_routes_.push_back({std::move(method), path, std::move(h)});
      return;
    }

    if (path.find('{') != std::string::npos ||
        path.find(')') != std::string::npos) {
      std::string pattern = method;
      pattern.push_back(' ');
      pattern.append(path);
      replace_all(pattern, "{}", "([^/]+)");
      regex_routes_.push_back({std::regex(pattern), std::move(h)});
      return;
    }

    std::string key = std::move(method);
    key.push_back(' ');
    key.append(path);
    auto [it, ok] = keys_.emplace(std::move(key));
    if (!ok) return;  // already registered
    handlers_.emplace(*it, std::move(h));
  }

  static void replace_all(std::string& text, std::string_view from,
                          std::string_view to) {
    if (from.empty()) return;
    size_t pos = 0;
    while ((pos = text.find(from, pos)) != std::string::npos) {
      text.replace(pos, from.size(), to);
      pos += to.size();
    }
  }

  static bool match_param_route(
      std::string_view pattern, std::string_view path,
      std::unordered_map<std::string, std::string>& params) {
    size_t pattern_pos = 0;
    size_t path_pos = 0;
    while (true) {
      auto pattern_end = pattern.find('/', pattern_pos);
      auto path_end = path.find('/', path_pos);
      auto pattern_segment = pattern.substr(
          pattern_pos, pattern_end == std::string_view::npos
                           ? pattern.size() - pattern_pos
                           : pattern_end - pattern_pos);
      auto path_segment = path.substr(
          path_pos, path_end == std::string_view::npos
                        ? path.size() - path_pos
                        : path_end - path_pos);

      if (!pattern_segment.empty() && pattern_segment.front() == '*') {
        params.emplace(std::string(pattern_segment.substr(1)),
                       std::string(path.substr(path_pos)));
        return true;
      }

      if (!pattern_segment.empty() && pattern_segment.front() == ':') {
        if (path_segment.empty()) return false;
        params.emplace(std::string(pattern_segment.substr(1)),
                       std::string(path_segment));
      }
      else if (pattern_segment != path_segment) {
        return false;
      }

      if (pattern_end == std::string_view::npos ||
          path_end == std::string_view::npos) {
        return pattern_end == path_end;
      }

      pattern_pos = pattern_end + 1;
      path_pos = path_end + 1;
    }
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
  std::vector<param_route> param_routes_;
  std::vector<regex_route> regex_routes_;
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
        router_(std::make_shared<h2_router>()),
        acceptor_(std::make_shared<asio::ip::tcp::acceptor>(
            ioc, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port))) {
    acceptor_->set_option(asio::ip::tcp::acceptor::reuse_address(true));
  }

  // Register handler for one or more HTTP methods.
  template <http_method... methods, typename Func>
  void set_http_handler(std::string path, Func handler) {
    router_->set_http_handler<methods...>(std::move(path), std::move(handler));
  }

  void set_default_handler(h2_handler handler) {
    router_->set_default_handler(std::move(handler));
  }

  void set_enable_connect_protocol(bool enabled) {
    enable_connect_protocol_ = enabled;
  }

  // Start the accept loop on exec.  Returns the bound port (useful when 0 was
  // passed to the constructor).
  uint16_t start(coro_io::ExecutorWrapper<>& exec) {
    executor_ = &exec;
    uint16_t p = acceptor_->local_endpoint().port();
    accept_loop(ioc_, acceptor_, router_, state_, exec,
                enable_connect_protocol_).via(&exec).detach();
    return p;
  }

  uint16_t port() const { return acceptor_->local_endpoint().port(); }

  // Stop accepting new connections and start graceful shutdown on active ones.
  void stop() {
    std::error_code ignored;
    acceptor_->close(ignored);

    std::vector<std::shared_ptr<coro_http2_connection>> conns;
    {
      std::scoped_lock lock(state_->mtx);
      conns.assign(state_->connections.begin(), state_->connections.end());
    }

    if (!executor_) return;
    for (auto& conn : conns) {
      conn->graceful_shutdown().via(executor_).detach();
    }
  }

 private:
  using conn_ptr = std::shared_ptr<coro_http2_connection>;
  using conn_set = std::set<conn_ptr, std::owner_less<conn_ptr>>;

  struct server_state {
    std::mutex mtx;
    conn_set   connections;
  };

  static async_simple::coro::Lazy<void> serve_one(
      std::shared_ptr<coro_http2_connection> conn) {
    co_await conn->start();
  }

  static async_simple::coro::Lazy<void> accept_loop(
      asio::io_context* ioc,
      std::shared_ptr<asio::ip::tcp::acceptor> acc,
      std::shared_ptr<h2_router> rp,
      std::shared_ptr<server_state> state,
      coro_io::ExecutorWrapper<>& exec,
      bool enable_connect_protocol) {
    while (true) {
      asio::ip::tcp::socket sock(exec.get_asio_executor());
      auto ec = co_await coro_io::async_accept(*acc, sock);
      if (ec) co_return;

      auto conn = std::make_shared<coro_http2_connection>(
          std::move(sock),
          [rp](h2_request& req, h2_response& resp)
              -> async_simple::coro::Lazy<void> {
            co_await rp->dispatch(req, resp);
          },
          &exec);
      conn->set_enable_connect_protocol(enable_connect_protocol);
      std::weak_ptr<coro_http2_connection> weak_conn = conn;
      conn->set_quit_callback([state, weak_conn]() {
        if (auto locked = weak_conn.lock()) {
          std::scoped_lock lock(state->mtx);
          state->connections.erase(locked);
        }
      });
      {
        std::scoped_lock lock(state->mtx);
        state->connections.insert(conn);
      }
      serve_one(std::move(conn)).via(&exec).detach();
    }
  }

  asio::io_context*          ioc_;
  std::shared_ptr<h2_router> router_;
  std::shared_ptr<asio::ip::tcp::acceptor> acceptor_;
  std::shared_ptr<server_state> state_ = std::make_shared<server_state>();
  coro_io::ExecutorWrapper<>* executor_ = nullptr;
  bool enable_connect_protocol_ = false;
};

}  // namespace cinatra::http2
