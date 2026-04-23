#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a prompt to RAMPART for evaluation.")
    parser.add_argument("prompt", nargs="?", help="Prompt text to evaluate. Reads stdin if omitted.")
    parser.add_argument("--url", help="RAMPART URL. Defaults to evaluate endpoint, or chat completions when --chat is set.")
    parser.add_argument("--model", default="gpt-4.1", help="Model name to include in the test request.")
    parser.add_argument("--chat", action="store_true", help="Call /v1/chat/completions and print the model response.")
    parser.add_argument("--customer", help="Customer name to send as X-RAMPART-Customer.")
    parser.add_argument("--client-id", help="Client/app ID to send as X-RAMPART-Client-Id.")
    parser.add_argument("--owner", help="Owner metadata to send as X-RAMPART-Owner.")
    parser.add_argument("--request-id", help="Request ID to send as X-Request-ID.")
    parser.add_argument("--api-key", help="API key to send as an Authorization bearer token.")
    parser.add_argument("--json", action="store_true", help="Print the raw JSON response.")
    args = parser.parse_args()

    prompt = args.prompt if args.prompt is not None else sys.stdin.read().strip()
    if not prompt:
        print("No prompt provided. Pass one as an argument or through stdin.", file=sys.stderr)
        return 2

    chat_request = {
        "model": args.model,
        "messages": [{"role": "user", "content": prompt}],
    }
    payload = chat_request if args.chat else {"request": chat_request}
    url = args.url or (
        "http://127.0.0.1:8080/v1/chat/completions"
        if args.chat
        else "http://127.0.0.1:8080/v1/rampart/evaluate"
    )

    try:
        headers = {}
        if args.api_key:
            headers["Authorization"] = f"Bearer {args.api_key}"
        if args.customer:
            headers["X-RAMPART-Customer"] = args.customer
        if args.client_id:
            headers["X-RAMPART-Client-Id"] = args.client_id
        if args.owner:
            headers["X-RAMPART-Owner"] = args.owner
        if args.request_id:
            headers["X-Request-ID"] = args.request_id
        response = post_json(url, payload, headers, raise_for_status=not args.chat)
    except RuntimeError as error:
        print(f"Request failed: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(response, indent=2, sort_keys=True))
        return 0

    if args.chat:
        print_chat_summary(response)
    else:
        print_summary(response)
    return 0


def post_json(
    url: str,
    payload: dict[str, Any],
    extra_headers: Optional[dict[str, str]] = None,
    raise_for_status: bool = True,
) -> dict[str, Any]:
    headers = {"content-type": "application/json"}
    headers.update(extra_headers or {})
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        if not raise_for_status:
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                return {"error": {"message": body, "type": "http_error", "code": error.code}}
        raise RuntimeError(f"HTTP {error.code}: {body}") from error
    except URLError as error:
        raise RuntimeError(error.reason) from error
    except TimeoutError as error:
        raise RuntimeError("request timed out") from error


def print_summary(response: dict[str, Any]) -> None:
    decision = response.get("decision")
    approved = decision == "accept"
    print(f"Approved: {'yes' if approved else 'no'}")

    violations = response.get("violations") or []
    if violations:
        print("\nEvaluations:")
        for violation in violations:
            policy_id = violation.get("policy_id", "unknown-policy")
            severity = violation.get("severity", "unknown")
            category = violation.get("category", "policy")
            source = violation.get("source", "unknown")
            path = violation.get("path")
            message = violation.get("message", "")
            location = f" at {path}" if path else ""
            print(f"- [{severity}] {policy_id} ({category}, {source}){location}: {message}")
    else:
        print("Evaluations: none")

    sanitized_prompt = extract_sanitized_prompt(response.get("sanitized_request"))
    if sanitized_prompt is not None:
        print("\nSanitized prompt:")
        print(sanitized_prompt)


def print_chat_summary(response: dict[str, Any]) -> None:
    if "error" in response:
        error = response["error"]
        print("Chat failed")
        print(f"Type: {error.get('type', 'unknown')}")
        print(f"Message: {error.get('message', '')}")
        violations = error.get("violations") or []
        if violations:
            print("\nEvaluations:")
            for violation in violations:
                policy_id = violation.get("policy_id", "unknown-policy")
                severity = violation.get("severity", "unknown")
                category = violation.get("category", "policy")
                source = violation.get("source", "unknown")
                message = violation.get("message", "")
                print(f"- [{severity}] {policy_id} ({category}, {source}): {message}")
        return

    choices = response.get("choices") or []
    if not choices:
        print(json.dumps(response, indent=2, sort_keys=True))
        return
    message = choices[0].get("message") or {}
    content = message.get("content")
    print("Chat response:")
    print(content if content is not None else json.dumps(message, indent=2, sort_keys=True))


def extract_sanitized_prompt(sanitized_request: Optional[dict[str, Any]]) -> Optional[str]:
    if not sanitized_request:
        return None
    messages = sanitized_request.get("messages")
    if not isinstance(messages, list) or not messages:
        return None
    content = messages[-1].get("content") if isinstance(messages[-1], dict) else None
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
        return "\n".join(parts) if parts else None
    return None


if __name__ == "__main__":
    raise SystemExit(main())
