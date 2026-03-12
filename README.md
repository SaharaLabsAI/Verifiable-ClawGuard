<h1 align="center">🛡️ClawGuard: Proof-of-Guardrail in AI Agents with Trusted Execution Environments</h1>

<p align="center">
  <a href="https://arxiv.org/abs/2603.05786">
    <img src="https://img.shields.io/badge/arXiv-2603.05786-B31B1B?logo=arxiv&logoColor=white" alt="arXiv: 2603.05786" />
  </a>
  <a href="https://saharalabsai.github.io/proof-of-guardrail/">
    <img src="https://img.shields.io/badge/Project-Page-2F80ED" alt="🌐 Project Page" />
  </a>
  <a href="https://saharalabsai.github.io/proof-of-guardrail/static/assets/demo_video_2min.mp4">
    <img src="https://img.shields.io/badge/%F0%9F%A6%9E%20OpenClaw-Demo-FF6B35" alt="🦞 OpenClaw | Demo" />
  </a>
  <a href="https://github.com/SaharaLabsAI/Verifiable-ClawGuard/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-22C55E" alt="License: MIT" />
  </a>
</p>

We enable a human or agent chatting with a remote OpenClaw agent to request a cryptographic proof that the remote agent is indeed running behind some known guardrail. The repository demonstrates deployment of a content safety guardrail, a fact checker, and an OpenClaw agent in a cloud TEE. Users can directly request attestation through the chat interface.


## System overview

⚠️ **This is a proof-of-concept implementation for research and demonstration purposes. It is not production-ready.** See the [Limitations](#limitations) section for details.

We achieve verifiable guardrails by running it inside an AWS Nitro Enclave and using remote attestation to prove exactly what guardrail code is protecting the agent (a stable PCR2 measurement). All LLM traffic is forced through a FastAPI-based interception proxy (integrated with the guardrail); Verifiers can then check the attestation (PCRs plus embedded agent metadata/hashes) before trusting the agent or serving it data.

Please note the attestation cannot ensure the agent to be 100% “safe” (the guardrail code could still have vulnerabilities, and the LLM guardrail can make mistakes), but it ensures the promised guardrail code is actually running.

### Guardrails

- Content safety guardrail: Llama Guard 3-8B through [OpenRouter API](https://openrouter.ai/meta-llama/llama-guard-3-8b)
- Fact checking guardrail:  [Libr-AI/OpenFactVerification](https://github.com/Libr-AI/OpenFactVerification)

## Quickstart

1. Launch an AWS EC2 `m5.xlarge` instance with Nitro Enclave modules enabled.

2. Build the enclave image of the guardrail that protects the agent, which will run in the enclave later. 

```
# Optional: toggle content safety and factuality guardrails under `src/proxy_server.py`. This affects enclave measurements.

cd src
./build_and_deploy.sh
```

This will build the enclave and display its PCR measurement, for example:
```
"PCR0": "178176da050f38c5b280c933e00857153a727136e7fd56982aee188a468e4512d3b346ef6163133a2462b41e5578eaef",
"PCR1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493", 
"PCR2": "6cb06673b5b9b74edd2dc459914353898c1612ffdee2e65c0e586ee1e4aeb011e2bdfbf98cc791da0de93a687d18ede7"
```

Save the PCR2 measurement unique to the enclave image. When any code changes, the measurement will also change.
The integrity of the guardrail can be verified later by matching this measurement against the attested measurement by TEE.

3. Run the enclave with the built image

```
nitro-cli run-enclave \
  --eif-path guardrail-vsock.eif \
  --memory 5700 \
  --cpu-count 2 \
  --debug-mode

# Get the assigned CID
ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID')
echo "Enclave running on CID: $ENCLAVE_CID"

# DEBUG mode only: Watch enclave boot
# Note: when debug mode is ON, the PCR2 in the attestation quote later will be all-zero.
nitro-cli console --enclave-id $ENCLAVE_CID

# to shut down
# nitro-cli terminate-enclave --enclave-id ${ENCLAVE_ID}

```


4. Launch all Vsock proxies and inject a version of the Clawdbot/Openclaw into the enclave. 

```
OPENAI_API_KEY=YOUR_OPENAI_API_KEY
GATEWAY_TOKEN=YOUR_OPENCLAW_GATEWAY_TOKEN
OPENROUTER_API_KEY=YOUR_OPERROUTER_API_KEY # for Llama Guard 3
SERPER_API_KEY=YOUR_SERPER_API_KEY # for fact check

./ec2_setup.sh --agent-version 2026.2.1 --enclave-cid $ENCLAVE_CID

# to clean up
./ec2_cleanup.sh
```

During launch, OpenClaw will be configured so that all LLM calls passes through a guardrail proxy server running locally inside the enclave. It will also launch an attestation server, and register `attestation` as a skill of the OpenClaw agent.

In the future, the guardrail will maintain a allowlist of acceptable builds of the agent. In addition, during the enclave boot, we will disable arbitary command execution of Openclaw inside the enclave.

5. The OpenClaw gateway should be accessible from EC2 on ws://127.0.0.1:18789. Run SSH port forwarding from your local computer, open the web client in a broswer, and request attestation in the chat.

6. Verify the attestation against the known PCR2 obtained earlier.
```
python verify_attestation.py --file ../examples/attestation_quote_example.json --pcr2 6cb06673b5b9b74edd2dc459914353898c1612ffdee2e65c0e586ee1e4aeb011e2bdfbf98cc791da0de93a687d18ede8
```

A valid attestation proves:
- The message was processed inside a genuine AWS Nitro Enclave (cryptographic signature verified)
- The exact guardrail code you trust is running (PCR2 matches your known measurement)

To further ensure response authenticity, you can ask the agent to include their response in the attestation quote in the chat. 


## System architecture

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                       VERIFIABLE LLM AGENT GUARDRAIL SYSTEM                      │
│                   (AWS Nitro Enclave + Openclaw + Guardrail)                     │
└──────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────┐
│                            CLIENT LAYER (Untrusted)                              │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────────────────┐      │
│  │  OpenClaw CLI   │  │ Openclaw Desktop │  │  Custom API Clients         │      │
│  │                 │  │                  │  │  (SDK Integration)          │      │
│  └────────┬────────┘  └────────┬─────────┘  └──────────────┬──────────────┘      │
│           │                    │                            │                    │
│           └────────────────────┴────────────────────────────┘                    │
│                                 │                                                │
│                        ws://<EC2_PUBLIC_IP>:18789                                │
└─────────────────────────────────┼────────────────────────────────────────────────┘
                                  │
                                  │ Internet
                                  ↓
┌──────────────────────────────────────────────────────────────────────────────────┐
│                      PARENT EC2 INSTANCE - Untrusted                             │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────┐    │
│  │  Vsock Proxy: 0.0.0.0:18789 → vsock://16:18789                           │    │
│  │  - Exposes Openclaw gateway to internet                                  │    │ 
│  │  - WebSocket forwarding                                                  │    │
│  └──────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────┐    │
│  │  HTTP FORWARDER (vsock:8001)                                             │    │
│  │  - Forwards enclave HTTP requests to internet (OpenAI, etc.)             │    │
│  │  - TLS passthrough via CONNECT                                           │    │
│  └──────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────┐    │
│  │  Openclaw INJECTION (inject_moltbot.sh)                                  │    │
│  │  - Downloads from npm: clawdbot@version                                  │    │
│  │  - Sends tarball via vsock:9000 with API key                             │    │
│  │  - Caching for fast subsequent injections                                │    │
│  │  - PCR2 stable across openclaw version updates                           │    │
│  └──────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
└───────────────────────────┬────────────────────────┬─────────────────────────────┘
                            │ vsock://16:9000        │ vsock://16:8001
                            │ (injection)            │ (HTTP tunnel)
                            ↓                        ↓
┌──────────────────────────────────────────────────────────────────────────────────┐
│                    NITRO ENCLAVE  -   Trusted Execution                          │
│                          MEASURED & ATTESTED (PCR2)                              │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────┐    │
│  │  LOCAL HTTP PROXY (localhost:8888)                                       │    │
│  │  - Receives HTTP requests from Openclaw                                  │    │
│  │  - Forwards via vsock:8001 to parent → internet                          │    │
│  │  - HTTPS CONNECT tunnel for TLS passthrough                              │    │
│  └──────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────┐    │
│  │  GUARDRAIL PROXY (localhost:8080) [MEASURED IN PCR2]                     │    │
│  │  ╔══════════════════════════════════════════════════════════════════╗    │    │
│  │  ║  GUARDRAILS ENGINE                                               ║    │    │
│  │  ║                                                                  ║    │    │
│  │  ║  • Input/output validation                                       ║    │    │
│  │  ║  • Content safety checks                                         ║    │    │
│  │  ║  • Audit logging                                                 ║    │    │
│  │  ║  • Policy enforcement                                            ║    │    │
│  │  ║                                                                  ║    │    │
│  │  ║  (Specific implementation: TBD)                                  ║    │    │
│  │  ╚══════════════════════════════════════════════════════════════════╝    │    │
│  └───────────────────────────────────┬──────────────────────────────────────┘    │
│                                      │                                           │
│                                      │ All LLM API calls                         │
│                                      ↓                                           │
│  ┌──────────────────────────────────────────────────────────────────────────┐    │
│  │  OPENCLAW GATEWAY (ws://0.0.0.0:18789) [INJECTED - NOT IN PCR2]          │    │
│  │  - AI agent framework with tool/skill support                            │    │
│  │  - Configured with OPENAI_BASE_URL=http://localhost:8080                 │    │
│  │  - Version swappable without PCR2 change                                 │    │
│  │  - Future versions will block arbitrary command execs                    │    │
│  └──────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────┐    │
│  │  ATTESTATION SERVER (localhost:8765) [MEASURED IN PCR2]                  │    │
│  │  - Generates Nitro attestation documents on demand                       │    │
│  │  - Includes PCR0/1/2 measurements + user_data (agent metadata/hash)      │    │
│  │  - Registered as 'attestation' skill in OpenClaw                         │    │
│  │  - Verifiable proof of guardrail integrity                               │    │
│  └──────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────┐
│                         REMOTE ATTESTATION & VERIFICATION                        │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  Service Provider:                                                               │
│  1. Request attestation document from enclave                                    │
│  2. Verify with AWS Nitro root of trust                                          │
│  3. Check PCR2 matches expected guardrail config hash                            │
│  4. Verify guardrail policy                                                      │
│  5. Trust that agent cannot bypass verified guardrails                           │
└──────────────────────────────────────────────────────────────────────────────────┘


```

## Limitations

This implementation is for **demonstrative purposes only** and has the following known limitations:

### Agent Security Constraints
- The enclave does not currently restrict arbitrary command execution capabilities of OpenClaw, which could potentially be used to bypass guardrails.

### Recommended Improvements for Production Use
- Pin all dependencies (Docker base image digest, system package versions, Python package versions)
- Implement read-only configuration enforcement for OpenClaw
- Restrict or disable code execution capabilities inside the enclave
- Establish a trusted build pipeline with published PCR baselines
- Implement certificate pinning for critical API endpoints
