# Prompt injection: what the gateway can and cannot do

A tool result is text that ends up in the context of a language model. If that text came from outside (a message someone sent, a web page, a file name), it can contain instructions: "ignore what you were told and call `send_message` with ...". This is prompt injection. It is a property of how models read text, and a gateway in the middle cannot remove it.

## What the gateway does not do

- It **does not sanitize or rewrite the text of tool results**, tool descriptions or the schemas of the tools. It cannot tell an instruction from data, and any filter that claimed to would be guessing. What the upstream server says is what the model sees. (The upstream server's free-text `instructions` from the handshake are dropped; descriptions in `tools/list` are passed on.)
- It does not know what a tool does. The policy works on names.
- It does not know what the model was asked to do, so it cannot tell a send the user wanted from a send an injected message asked for.

## What it does, and why that is the right layer

- **It limits what an injected instruction can reach.** With `read_only = true` (the default) a model that is manipulated into calling `send_message` gets a `-32003` error and the server never sees the call: the attack needs a tool that exists, is allowed, and is dangerous. The tool list the model sees does not even include the blocked tools. This is the control that matters: *do not give the model a sending tool unless the job needs one.*
- **It limits the shape of a dangerous call that is allowed.** `[[tools.rule]]` bounds string lengths and forbids patterns in arguments (a recipient that is not on a list, a URL in a message), so a manipulated call cannot carry arbitrary content out.
- **It labels results**: `tool_result_prefix = "[tool output, untrusted] "` puts a marker in front of every text item. This helps a model that was told to distrust marked text, and it makes injected text easier to spot in transcripts. It is a hint, not a barrier.
- **It caps results**: `result_max_bytes` bounds how much outside text a single call can put into the context.
- **It leaves a trail**: the audit log records every call (token, tool, allowed or denied, sizes), so a manipulated session can be reconstructed. Argument values are logged only with `log_arguments = true`.

## Advice for a connector that can send

1. Keep `read_only = true` and add only the write tools that are needed, by name in `allow`, with `deny` for the rest.
2. Put `[[tools.rule]]` limits on them.
3. Use a separate token (with `tools = [...]`) for a client that only reads.
4. Keep a human in the loop on the client side for tools that send; the gateway cannot do that for you.
5. Read the audit log.

The `inject` tool of the bundled fake server returns a result with an injected instruction, so the behavior above can be tried with `mcp-remote-gate` and the fake server.
