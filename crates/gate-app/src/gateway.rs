//! The request handler of the gateway: everything that happens between a parsed HTTP request
//! and the HTTP response, independent of how the bytes travel.
//!
//! The order of the checks is part of the security design. Cheap refusals that need no secret
//! come first (kill switch, path, Host, Origin), then authentication, then the per-token rate
//! limit, then the request format, and only then the tool policy. Nothing reaches the upstream
//! server unless every step passed, and every request leaves one audit record.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use gate_domain::audit::{AuditRecord, Outcome};
use gate_domain::auth::{bearer_token, Authenticator, BearerError, Scope, TokenEntry};
use gate_domain::config::Config;
use gate_domain::hostcheck::{HostError, HostPolicy};
use gate_domain::json::{self, Value};
use gate_domain::jsonrpc::{self, Message, RpcError};
use gate_domain::mcp::{
    filter_tools, parse_call_params, shape_call_result, valid_protocol_version,
};
use gate_domain::policy::{Decision, ToolPolicy};
use gate_domain::ratelimit::{RateDecision, RateLimiter};
use gate_domain::sanitize::{escape_control, redact_value, truncate_chars};

use crate::ports::{AuditSink, Clock, KillSwitch, Level, Logger};
use crate::upstream::{UpstreamError, UpstreamPort};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Post,
    Get,
    Delete,
    Options,
    Other,
}

/// A parsed HTTP request, reduced to what the gateway looks at.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: HttpMethod,
    /// The request target without a query string.
    pub path: String,
    pub host: Option<String>,
    pub origin: Option<String>,
    pub authorization: Option<String>,
    pub content_type: Option<String>,
    pub accept: Option<String>,
    pub protocol_version: Option<String>,
    pub body: Vec<u8>,
    /// The IP address of the peer, without the port.
    pub peer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    /// A JSON body, empty for 202.
    pub body: Vec<u8>,
    pub retry_after_secs: Option<u64>,
    pub allow: Option<&'static str>,
    /// Add `WWW-Authenticate: Bearer`.
    pub challenge: bool,
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub endpoint: String,
    pub hosts: HostPolicy,
    pub max_request_bytes: usize,
    pub request_timeout_ms: u64,
    pub requests_per_minute: u32,
    pub burst: u32,
    pub failed_auth_per_minute: u32,
    pub result_max_bytes: Option<usize>,
    pub tool_result_prefix: Option<String>,
    pub log_arguments: bool,
    pub arguments_max_chars: usize,
    pub gate_version: String,
}

impl GatewayConfig {
    pub fn from_config(config: &Config, gate_version: &str) -> GatewayConfig {
        GatewayConfig {
            endpoint: config.server.endpoint.clone(),
            hosts: config.server.hosts.clone(),
            max_request_bytes: config.server.max_request_bytes,
            request_timeout_ms: config.server.request_timeout_ms,
            requests_per_minute: config.limits.requests_per_minute,
            burst: config.limits.burst,
            failed_auth_per_minute: config.limits.failed_auth_per_minute,
            result_max_bytes: config.limits.result_max_bytes,
            tool_result_prefix: config.limits.tool_result_prefix.clone(),
            log_arguments: config.audit.log_arguments,
            arguments_max_chars: config.audit.arguments_max_chars,
            gate_version: gate_version.to_string(),
        }
    }
}

/// The ports the gateway runs on.
#[derive(Clone)]
pub struct Ports {
    pub upstream: Arc<dyn UpstreamPort>,
    pub clock: Arc<dyn Clock>,
    pub audit: Arc<dyn AuditSink>,
    pub kill: Arc<dyn KillSwitch>,
    pub log: Arc<dyn Logger>,
}

pub struct Gateway {
    cfg: GatewayConfig,
    auth: Authenticator,
    policy: ToolPolicy,
    ports: Ports,
    token_limits: Mutex<RateLimiter>,
    failed_auth: Mutex<RateLimiter>,
    unauth_log: Mutex<UnauthLog>,
}

/// Audit lines of unauthenticated requests are limited, so that a flood of bad requests cannot
/// fill the disk; the number of dropped lines is reported on the next line that passes.
struct UnauthLog {
    limiter: RateLimiter,
    suppressed: u64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What is known about a request while it is handled, for the audit record.
struct Ctx<'a> {
    req: &'a Request,
    started: u64,
    token: Option<String>,
    method: String,
    tool: Option<String>,
    arguments: Option<String>,
}

fn http_response(status: u16, code: i64, message: &str) -> Response {
    Response {
        status,
        body: jsonrpc::response_error(&Value::Null, &RpcError::new(code, message))
            .to_json()
            .into_bytes(),
        retry_after_secs: None,
        allow: None,
        challenge: false,
    }
}

fn json_response(status: u16, value: &Value) -> Response {
    Response {
        status,
        body: value.to_json().into_bytes(),
        retry_after_secs: None,
        allow: None,
        challenge: false,
    }
}

fn accepted() -> Response {
    Response {
        status: 202,
        body: Vec::new(),
        retry_after_secs: None,
        allow: None,
        challenge: false,
    }
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Response {
    json_response(
        200,
        &jsonrpc::response_error(id, &RpcError::new(code, message)),
    )
}

fn accepts_json(accept: &str) -> bool {
    accept.split(',').any(|item| {
        let media = item
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        matches!(media.as_str(), "application/json" | "application/*" | "*/*")
    })
}

fn is_json_content_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/json")
}

fn retry_secs(ms: u64) -> u64 {
    ms.div_ceil(1000).max(1)
}

impl Gateway {
    pub fn new(
        cfg: GatewayConfig,
        auth: Authenticator,
        policy: ToolPolicy,
        ports: Ports,
    ) -> Gateway {
        let failed = cfg.failed_auth_per_minute;
        Gateway {
            token_limits: Mutex::new(RateLimiter::new(cfg.requests_per_minute, cfg.burst)),
            failed_auth: Mutex::new(RateLimiter::new(failed, failed)),
            unauth_log: Mutex::new(UnauthLog {
                limiter: RateLimiter::new(60, 30),
                suppressed: 0,
            }),
            cfg,
            auth,
            policy,
            ports,
        }
    }

    pub fn handle(&self, req: &Request) -> Response {
        let mut ctx = Ctx {
            req,
            started: self.ports.clock.mono_ms(),
            token: None,
            method: format!("http {}", method_name(req.method)),
            tool: None,
            arguments: None,
        };
        if self.ports.kill.engaged() {
            let mut r = http_response(
                503,
                jsonrpc::UPSTREAM_UNAVAILABLE,
                "the gateway is switched off",
            );
            r.retry_after_secs = Some(30);
            return self.finish(&ctx, Outcome::Denied, "kill_switch", r);
        }
        if req.path != self.cfg.endpoint {
            return self.finish(
                &ctx,
                Outcome::Denied,
                "not_found",
                http_response(404, jsonrpc::INVALID_REQUEST, "not found"),
            );
        }
        match self.cfg.hosts.check_host(req.host.as_deref()) {
            Ok(()) => {}
            Err(HostError::Missing | HostError::NotAllowed) => {
                return self.finish(
                    &ctx,
                    Outcome::Denied,
                    "host_rejected",
                    http_response(403, jsonrpc::FORBIDDEN, "host not allowed"),
                );
            }
        }
        if self.cfg.hosts.check_origin(req.origin.as_deref()).is_err() {
            return self.finish(
                &ctx,
                Outcome::Denied,
                "origin_rejected",
                http_response(403, jsonrpc::FORBIDDEN, "origin not allowed"),
            );
        }
        let token = match self.authenticate(req) {
            Ok(token) => token,
            Err(response_reason) => {
                let (reason, response) = *response_reason;
                return self.finish(&ctx, Outcome::Denied, reason, response);
            }
        };
        ctx.token = Some(token.id.as_str().to_string());
        let now = self.ports.clock.mono_ms();
        if let RateDecision::Limited { retry_after_ms } =
            lock(&self.token_limits).check(token.id.as_str(), now)
        {
            let mut r = http_response(429, jsonrpc::BUSY, "rate limit exceeded");
            r.retry_after_secs = Some(retry_secs(retry_after_ms));
            return self.finish(&ctx, Outcome::Denied, "rate_limited", r);
        }
        if req.method != HttpMethod::Post {
            let mut r = http_response(405, jsonrpc::INVALID_REQUEST, "use POST");
            r.allow = Some("POST");
            return self.finish(&ctx, Outcome::Denied, "method_not_allowed", r);
        }
        if let Err((reason, response)) = self.check_format(req) {
            return self.finish(&ctx, Outcome::Denied, reason, response);
        }
        let message = match std::str::from_utf8(&req.body)
            .ok()
            .and_then(|t| json::parse(t).ok())
        {
            Some(value) => jsonrpc::classify(value),
            None => {
                let r = json_response(
                    400,
                    &jsonrpc::response_error(
                        &Value::Null,
                        &RpcError::new(jsonrpc::PARSE_ERROR, "the body is not valid JSON"),
                    ),
                );
                return self.finish(&ctx, Outcome::Denied, "bad_json", r);
            }
        };
        match message {
            Err(rejection) => {
                let r = json_response(
                    400,
                    &jsonrpc::response_error(&rejection.id, &rejection.error),
                );
                self.finish(&ctx, Outcome::Denied, "bad_jsonrpc", r)
            }
            Ok(Message::Notification { method, .. }) => {
                ctx.method = truncate_chars(&method, 64);
                self.finish(&ctx, Outcome::Allowed, "ok", accepted())
            }
            Ok(Message::Response { .. }) => {
                ctx.method = "response".into();
                self.finish(&ctx, Outcome::Allowed, "ok", accepted())
            }
            Ok(Message::Request { id, method, params }) => {
                ctx.method = truncate_chars(&method, 64);
                self.dispatch(&mut ctx, token, &id, &method, params)
            }
        }
    }

    /// The token of the request, or the refusal to send.
    fn authenticate(&self, req: &Request) -> Result<&TokenEntry, Box<(&'static str, Response)>> {
        let refuse = |reason: &'static str, response: Response| Box::new((reason, response));
        let credential = match bearer_token(req.authorization.as_deref()) {
            Ok(credential) => credential,
            Err(e) => {
                let reason = if e == BearerError::Missing {
                    "missing_token"
                } else {
                    "malformed_token"
                };
                return Err(refuse(reason, self.unauthorized()));
            }
        };
        match self.auth.authenticate(credential) {
            Some(token) => Ok(token),
            None => Err(refuse("bad_token", self.unauthorized())),
        }
    }

    fn unauthorized(&self) -> Response {
        let now = self.ports.clock.mono_ms();
        match lock(&self.failed_auth).check("failed", now) {
            RateDecision::Allowed => {
                let mut r = http_response(401, jsonrpc::FORBIDDEN, "unauthorized");
                r.challenge = true;
                r
            }
            RateDecision::Limited { retry_after_ms } => {
                let mut r = http_response(429, jsonrpc::BUSY, "too many failed attempts");
                r.retry_after_secs = Some(retry_secs(retry_after_ms));
                r
            }
        }
    }

    fn check_format(&self, req: &Request) -> Result<(), (&'static str, Response)> {
        if !req
            .content_type
            .as_deref()
            .is_some_and(is_json_content_type)
        {
            return Err((
                "unsupported_media_type",
                http_response(415, jsonrpc::INVALID_REQUEST, "send application/json"),
            ));
        }
        if req.accept.as_deref().is_some_and(|a| !accepts_json(a)) {
            return Err((
                "not_acceptable",
                http_response(
                    406,
                    jsonrpc::INVALID_REQUEST,
                    "the response is application/json",
                ),
            ));
        }
        if req
            .protocol_version
            .as_deref()
            .is_some_and(|v| !valid_protocol_version(v))
        {
            return Err((
                "bad_protocol_version",
                http_response(
                    400,
                    jsonrpc::INVALID_REQUEST,
                    "invalid MCP-Protocol-Version",
                ),
            ));
        }
        if req.body.len() > self.cfg.max_request_bytes {
            return Err((
                "too_large",
                http_response(413, jsonrpc::INVALID_REQUEST, "request too large"),
            ));
        }
        Ok(())
    }

    fn dispatch(
        &self,
        ctx: &mut Ctx<'_>,
        token: &TokenEntry,
        id: &Value,
        method: &str,
        params: Option<Value>,
    ) -> Response {
        match method {
            "initialize" => match self.ports.upstream.info() {
                Ok(info) => {
                    let result = info.result_for_client(&self.cfg.gate_version);
                    self.finish(
                        ctx,
                        Outcome::Allowed,
                        "ok",
                        json_response(200, &jsonrpc::response_ok(id, result)),
                    )
                }
                Err(e) => self.upstream_failure(ctx, id, &e),
            },
            "ping" => self.finish(
                ctx,
                Outcome::Allowed,
                "ok",
                json_response(200, &jsonrpc::response_ok(id, Value::Object(vec![]))),
            ),
            "tools/list" => self.tools_list(ctx, token, id, params.as_ref()),
            "tools/call" => self.tools_call(ctx, token, id, params.as_ref()),
            _ => self.finish(
                ctx,
                Outcome::Denied,
                "method_not_allowed",
                rpc_error(
                    id,
                    jsonrpc::METHOD_NOT_FOUND,
                    "this method is not available through the gateway",
                ),
            ),
        }
    }

    fn tools_list(
        &self,
        ctx: &mut Ctx<'_>,
        token: &TokenEntry,
        id: &Value,
        params: Option<&Value>,
    ) -> Response {
        if !token.has_scope(Scope::ToolsList) {
            return self.finish(
                ctx,
                Outcome::Denied,
                "scope_missing",
                rpc_error(id, jsonrpc::FORBIDDEN, "the token has no tools:list scope"),
            );
        }
        let forwarded = params
            .and_then(|p| p.get("cursor"))
            .and_then(Value::as_str)
            .map(|c| Value::object([("cursor", Value::str(c))]));
        match self
            .ports
            .upstream
            .request("tools/list", forwarded, self.cfg.request_timeout_ms)
        {
            Ok(result) => {
                let (filtered, _) = filter_tools(result, &|name| {
                    self.policy.decide_for(token, name).is_allowed()
                });
                self.finish(
                    ctx,
                    Outcome::Allowed,
                    "ok",
                    json_response(200, &jsonrpc::response_ok(id, filtered)),
                )
            }
            Err(e) => self.upstream_failure(ctx, id, &e),
        }
    }

    fn tools_call(
        &self,
        ctx: &mut Ctx<'_>,
        token: &TokenEntry,
        id: &Value,
        params: Option<&Value>,
    ) -> Response {
        if !token.has_scope(Scope::ToolsCall) {
            return self.finish(
                ctx,
                Outcome::Denied,
                "scope_missing",
                rpc_error(id, jsonrpc::FORBIDDEN, "the token has no tools:call scope"),
            );
        }
        let call = match parse_call_params(params) {
            Ok(call) => call,
            Err(why) => {
                return self.finish(
                    ctx,
                    Outcome::Denied,
                    "bad_params",
                    rpc_error(id, jsonrpc::INVALID_PARAMS, why),
                )
            }
        };
        ctx.tool = Some(call.name.to_string());
        if self.cfg.log_arguments {
            ctx.arguments = call.arguments.map(|a| {
                let text = redact_value(a).to_json();
                escape_control(&text, self.cfg.arguments_max_chars)
            });
        }
        if let Decision::Deny(reason) = self.policy.decide_for(token, call.name) {
            let message = format!(
                "the tool \"{}\" is not allowed by the gateway policy",
                escape_control(call.name, 64)
            );
            return self.finish(
                ctx,
                Outcome::Denied,
                reason.code(),
                rpc_error(id, jsonrpc::FORBIDDEN, &message),
            );
        }
        if let Err(violation) = self.policy.check_arguments(call.name, call.arguments) {
            let message = format!(
                "the arguments are refused by the gateway policy ({})",
                violation.code()
            );
            return self.finish(
                ctx,
                Outcome::Denied,
                violation.code(),
                rpc_error(id, jsonrpc::FORBIDDEN, &message),
            );
        }
        // The intent is on record before the server hears of the call: if it cannot be written the
        // call does not happen, and if the gateway or the machine dies during the call the log still
        // says that it was started. The completion record follows in `finish`.
        if let Err(e) = self.ports.audit.record(&self.intent_record(ctx)) {
            self.ports.log.log(
                Level::Error,
                &format!(
                    "cannot write the audit log, refusing the tool call: {}",
                    escape_control(&e, 160)
                ),
            );
            let mut r = http_response(
                503,
                jsonrpc::UPSTREAM_UNAVAILABLE,
                "the audit log is unavailable",
            );
            r.retry_after_secs = Some(30);
            return self.finish(ctx, Outcome::Denied, "audit_unavailable", r);
        }
        let mut forwarded = vec![("name".to_string(), Value::str(call.name))];
        if let Some(args) = call.arguments {
            forwarded.push(("arguments".to_string(), args.clone()));
        }
        match self.ports.upstream.request(
            "tools/call",
            Some(Value::Object(forwarded)),
            self.cfg.request_timeout_ms,
        ) {
            Ok(result) => {
                match shape_call_result(
                    result,
                    self.cfg.result_max_bytes,
                    self.cfg.tool_result_prefix.as_deref(),
                ) {
                    Ok(shaped) => self.finish(
                        ctx,
                        Outcome::Allowed,
                        "ok",
                        json_response(200, &jsonrpc::response_ok(id, shaped)),
                    ),
                    Err(_) => self.finish(
                        ctx,
                        Outcome::Error,
                        "result_too_large",
                        rpc_error(
                            id,
                            jsonrpc::RESULT_TOO_LARGE,
                            "the tool result is larger than the gateway allows",
                        ),
                    ),
                }
            }
            Err(e) => self.upstream_failure(ctx, id, &e),
        }
    }

    fn upstream_failure(&self, ctx: &Ctx<'_>, id: &Value, error: &UpstreamError) -> Response {
        match error {
            UpstreamError::Unavailable(why) => {
                let mut r = json_response(
                    503,
                    &jsonrpc::response_error(
                        id,
                        &RpcError::new(
                            jsonrpc::UPSTREAM_UNAVAILABLE,
                            "the upstream server is not available",
                        ),
                    ),
                );
                r.retry_after_secs = Some(5);
                self.ports.log.log(
                    Level::Warn,
                    &format!("upstream unavailable: {}", escape_control(why, 160)),
                );
                self.finish(ctx, Outcome::Error, "upstream_unavailable", r)
            }
            UpstreamError::Busy => {
                let mut r = json_response(
                    429,
                    &jsonrpc::response_error(
                        id,
                        &RpcError::new(jsonrpc::BUSY, "the upstream server is busy"),
                    ),
                );
                r.retry_after_secs = Some(1);
                self.finish(ctx, Outcome::Error, "busy", r)
            }
            UpstreamError::Timeout => self.finish(
                ctx,
                Outcome::Error,
                "timeout",
                rpc_error(
                    id,
                    jsonrpc::UPSTREAM_TIMEOUT,
                    "the upstream server did not answer in time",
                ),
            ),
            UpstreamError::TooLarge => self.finish(
                ctx,
                Outcome::Error,
                "result_too_large",
                rpc_error(
                    id,
                    jsonrpc::RESULT_TOO_LARGE,
                    "the tool result is larger than the gateway allows",
                ),
            ),
            UpstreamError::Rpc(e) => {
                // the code and a bounded message of the server; its free-form data is not passed on
                let message = escape_control(&e.message, 500);
                self.finish(
                    ctx,
                    Outcome::Error,
                    "upstream_error",
                    rpc_error(id, e.code, &message),
                )
            }
        }
    }

    /// The record written before an allowed tool call is forwarded.
    fn intent_record(&self, ctx: &Ctx<'_>) -> AuditRecord {
        AuditRecord {
            unix_ms: self.ports.clock.unix_ms(),
            token: ctx.token.clone(),
            peer: ctx.req.peer.clone(),
            method: ctx.method.clone(),
            tool: ctx.tool.clone(),
            outcome: Outcome::Started,
            reason: "intent".to_string(),
            duration_ms: 0,
            request_bytes: ctx.req.body.len(),
            response_bytes: 0,
            arguments: ctx.arguments.clone(),
            suppressed: 0,
        }
    }

    /// Records the request in the audit log and returns the response.
    fn finish(
        &self,
        ctx: &Ctx<'_>,
        outcome: Outcome,
        reason: &str,
        response: Response,
    ) -> Response {
        let suppressed = if ctx.token.is_none() {
            let now = self.ports.clock.mono_ms();
            let mut log = lock(&self.unauth_log);
            match log.limiter.check("unauthenticated", now) {
                RateDecision::Allowed => std::mem::take(&mut log.suppressed),
                RateDecision::Limited { .. } => {
                    log.suppressed += 1;
                    return response;
                }
            }
        } else {
            0
        };
        let record = AuditRecord {
            unix_ms: self.ports.clock.unix_ms(),
            token: ctx.token.clone(),
            peer: ctx.req.peer.clone(),
            method: ctx.method.clone(),
            tool: ctx.tool.clone(),
            outcome,
            reason: reason.to_string(),
            duration_ms: self.ports.clock.mono_ms().saturating_sub(ctx.started),
            request_bytes: ctx.req.body.len(),
            response_bytes: response.body.len(),
            arguments: ctx.arguments.clone(),
            suppressed,
        };
        if let Err(e) = self.ports.audit.record(&record) {
            self.ports.log.log(
                Level::Error,
                &format!("cannot write the audit log: {}", escape_control(&e, 160)),
            );
        }
        response
    }
}

fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Post => "POST",
        HttpMethod::Get => "GET",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Other => "other",
    }
}
