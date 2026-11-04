//! JSON-RPC 2.0 message classification and construction, as used by MCP.

use crate::json::Value;

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;
/// The upstream server did not answer within the call timeout.
pub const UPSTREAM_TIMEOUT: i64 = -32001;
/// The upstream server is not running or went away during the call.
pub const UPSTREAM_UNAVAILABLE: i64 = -32002;
/// The gateway policy does not allow the call.
pub const FORBIDDEN: i64 = -32003;
/// The result is larger than the gateway allows.
pub const RESULT_TOO_LARGE: i64 = -32004;
/// Too many calls are in flight.
pub const BUSY: i64 = -32005;

#[derive(Debug, Clone, PartialEq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl RpcError {
    pub fn new(code: i64, message: &str) -> RpcError {
        RpcError {
            code,
            message: message.to_string(),
            data: None,
        }
    }

    pub fn to_value(&self) -> Value {
        let mut members = vec![
            ("code".to_string(), Value::int(self.code)),
            ("message".to_string(), Value::str(&self.message)),
        ];
        if let Some(data) = &self.data {
            members.push(("data".to_string(), data.clone()));
        }
        Value::Object(members)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Request {
        id: Value,
        method: String,
        params: Option<Value>,
    },
    Notification {
        method: String,
        params: Option<Value>,
    },
    Response {
        id: Value,
        outcome: Result<Value, RpcError>,
    },
}

/// A message that is not valid JSON-RPC, with the id to answer it under (`null` when unknown).
#[derive(Debug, Clone, PartialEq)]
pub struct Rejection {
    pub id: Value,
    pub error: RpcError,
}

fn reject(id: Value, message: &str) -> Rejection {
    Rejection {
        id,
        error: RpcError::new(INVALID_REQUEST, message),
    }
}

/// An id is a string or a number; MCP forbids `null`.
fn is_valid_id(id: &Value) -> bool {
    matches!(id, Value::String(_) | Value::Number(_))
}

pub fn classify(value: Value) -> Result<Message, Rejection> {
    let Value::Object(_) = &value else {
        let what = if matches!(value, Value::Array(_)) {
            "batches are not supported"
        } else {
            "a message must be an object"
        };
        return Err(reject(Value::Null, what));
    };
    let id = value.get("id");
    let answer_id = id
        .filter(|id| is_valid_id(id))
        .cloned()
        .unwrap_or(Value::Null);
    if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(reject(answer_id, "jsonrpc must be \"2.0\""));
    }
    if let Some(method) = value.get("method") {
        let Some(method) = method.as_str() else {
            return Err(reject(answer_id, "method must be a string"));
        };
        let params = value.get("params").cloned();
        if let Some(p) = &params {
            if !matches!(p, Value::Object(_) | Value::Array(_)) {
                return Err(Rejection {
                    id: answer_id,
                    error: RpcError::new(INVALID_PARAMS, "params must be an object or an array"),
                });
            }
        }
        return match id {
            None => Ok(Message::Notification {
                method: method.to_string(),
                params,
            }),
            Some(id) if is_valid_id(id) => Ok(Message::Request {
                id: id.clone(),
                method: method.to_string(),
                params,
            }),
            Some(_) => Err(reject(Value::Null, "id must be a string or a number")),
        };
    }
    let Some(id) = id else {
        return Err(reject(Value::Null, "a message needs a method or an id"));
    };
    if !is_valid_id(id) && !id.is_null() {
        return Err(reject(Value::Null, "id must be a string or a number"));
    }
    match (value.get("result"), value.get("error")) {
        (Some(result), None) => Ok(Message::Response {
            id: id.clone(),
            outcome: Ok(result.clone()),
        }),
        (None, Some(error)) => {
            let code = error.get("code").and_then(|c| match c {
                Value::Number(n) => n.parse::<i64>().ok(),
                _ => None,
            });
            let message = error.get("message").and_then(Value::as_str);
            match (code, message) {
                (Some(code), Some(message)) => Ok(Message::Response {
                    id: id.clone(),
                    outcome: Err(RpcError {
                        code,
                        message: message.to_string(),
                        data: error.get("data").cloned(),
                    }),
                }),
                _ => Err(reject(
                    answer_id,
                    "error needs an integer code and a string message",
                )),
            }
        }
        _ => Err(reject(
            answer_id,
            "a response has exactly one of result and error",
        )),
    }
}

pub fn request(id: &Value, method: &str, params: Option<Value>) -> Value {
    let mut members = vec![
        ("jsonrpc".to_string(), Value::str("2.0")),
        ("id".to_string(), id.clone()),
        ("method".to_string(), Value::str(method)),
    ];
    if let Some(params) = params {
        members.push(("params".to_string(), params));
    }
    Value::Object(members)
}

pub fn notification(method: &str, params: Option<Value>) -> Value {
    let mut members = vec![
        ("jsonrpc".to_string(), Value::str("2.0")),
        ("method".to_string(), Value::str(method)),
    ];
    if let Some(params) = params {
        members.push(("params".to_string(), params));
    }
    Value::Object(members)
}

pub fn response_ok(id: &Value, result: Value) -> Value {
    Value::Object(vec![
        ("jsonrpc".to_string(), Value::str("2.0")),
        ("id".to_string(), id.clone()),
        ("result".to_string(), result),
    ])
}

pub fn response_error(id: &Value, error: &RpcError) -> Value {
    Value::Object(vec![
        ("jsonrpc".to_string(), Value::str("2.0")),
        ("id".to_string(), id.clone()),
        ("error".to_string(), error.to_value()),
    ])
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;
    use crate::json::parse;

    fn classify_text(text: &str) -> Result<Message, Rejection> {
        classify(parse(text).unwrap())
    }

    #[test]
    fn requests_notifications_and_responses() {
        assert_eq!(
            classify_text(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).unwrap(),
            Message::Request {
                id: Value::int(1),
                method: "tools/list".into(),
                params: None
            }
        );
        assert_eq!(
            classify_text(r#"{"jsonrpc":"2.0","id":"a","method":"x","params":{"k":1}}"#).unwrap(),
            Message::Request {
                id: Value::str("a"),
                method: "x".into(),
                params: Some(parse(r#"{"k":1}"#).unwrap())
            }
        );
        assert_eq!(
            classify_text(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).unwrap(),
            Message::Notification {
                method: "notifications/initialized".into(),
                params: None
            }
        );
        assert_eq!(
            classify_text(r#"{"jsonrpc":"2.0","id":7,"result":{"ok":true}}"#).unwrap(),
            Message::Response {
                id: Value::int(7),
                outcome: Ok(parse(r#"{"ok":true}"#).unwrap())
            }
        );
        assert_eq!(
            classify_text(
                r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"no","data":[1]}}"#
            )
            .unwrap(),
            Message::Response {
                id: Value::int(7),
                outcome: Err(RpcError {
                    code: -32601,
                    message: "no".into(),
                    data: Some(parse("[1]").unwrap())
                })
            }
        );
        assert!(matches!(
            classify_text(r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"p"}}"#)
                .unwrap(),
            Message::Response { .. }
        ));
    }

    #[test]
    fn rejects_malformed_messages() {
        for bad in [
            r#"[]"#,
            r#"[{"jsonrpc":"2.0","id":1,"method":"x"}]"#,
            r#"1"#,
            r#"{"id":1,"method":"x"}"#,
            r#"{"jsonrpc":"1.0","id":1,"method":"x"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":5}"#,
            r#"{"jsonrpc":"2.0","id":null,"method":"x"}"#,
            r#"{"jsonrpc":"2.0","id":true,"method":"x"}"#,
            r#"{"jsonrpc":"2.0","id":{},"method":"x"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"x","params":5}"#,
            r#"{"jsonrpc":"2.0"}"#,
            r#"{"jsonrpc":"2.0","id":1}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":1,"error":{"code":1,"message":"m"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":"x","message":"m"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":"m"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":1}}"#,
        ] {
            assert!(classify_text(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn rejection_answers_under_the_request_id_when_it_is_usable() {
        let r = classify_text(r#"{"jsonrpc":"1.0","id":5,"method":"x"}"#).unwrap_err();
        assert_eq!(r.id, Value::int(5));
        assert_eq!(r.error.code, INVALID_REQUEST);
        let r = classify_text(r#"{"jsonrpc":"2.0","id":5,"method":"x","params":3}"#).unwrap_err();
        assert_eq!((r.id, r.error.code), (Value::int(5), INVALID_PARAMS));
        let r = classify_text(r#"{"jsonrpc":"2.0","id":[1],"method":"x"}"#).unwrap_err();
        assert_eq!(r.id, Value::Null);
        assert_eq!(
            classify_text("[]").unwrap_err().error.message,
            "batches are not supported"
        );
    }

    #[test]
    fn builders_produce_wire_messages() {
        let id = Value::int(3);
        assert_eq!(
            request(&id, "ping", None).to_json(),
            r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#
        );
        assert_eq!(
            request(&id, "m", Some(Value::object([("a", Value::Null)]))).to_json(),
            r#"{"jsonrpc":"2.0","id":3,"method":"m","params":{"a":null}}"#
        );
        assert_eq!(
            notification("n", None).to_json(),
            r#"{"jsonrpc":"2.0","method":"n"}"#
        );
        assert_eq!(
            response_ok(&id, Value::Null).to_json(),
            r#"{"jsonrpc":"2.0","id":3,"result":null}"#
        );
        let err = RpcError {
            code: FORBIDDEN,
            message: "no".into(),
            data: Some(Value::Bool(true)),
        };
        assert_eq!(
            response_error(&Value::Null, &err).to_json(),
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32003,"message":"no","data":true}}"#
        );
        assert_eq!(
            RpcError::new(INTERNAL_ERROR, "x").to_value().to_json(),
            r#"{"code":-32603,"message":"x"}"#
        );
    }

    #[test]
    fn what_the_builders_write_classifies_back() {
        let id = Value::str("abc");
        let msg = classify(request(
            &id,
            "tools/call",
            Some(Value::object([("name", Value::str("x"))])),
        ))
        .unwrap();
        assert!(matches!(msg, Message::Request { .. }));
        let msg = classify(response_error(&id, &RpcError::new(BUSY, "busy"))).unwrap();
        assert_eq!(
            msg,
            Message::Response {
                id,
                outcome: Err(RpcError::new(BUSY, "busy"))
            }
        );
    }
}
