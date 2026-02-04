# ClawGuard: Verifiable Guardrails for Openclaw Agents

> *"Committed to beneficial AI that protects humanity"* - Cryptographically verify whether the agent you talk to adheres to this principle.


We enable a human or agent chatting with a remote OpenClaw (Clawdbot / Moltbot) agent to request a cryptographic proof that the remote agent is indeed running behind some known guardrail. The repository demonstrates deployment of a simple guardrail and OpenClaw agent in a cloud TEE. For demonstrative purposes only, users can directly request attestation through the chat interface.


![attestation_request_via_chat](assets/demo_attestation_request.png)
![attestation_response_via_chat](assets/demo_attestation_response.png)

Video demo: Proving a response is generated after a guardrail

<video src="assets/attested_response_generation.mp4" controls></video>


Verifiable guardrails matter broadly in human-to-agent or agent-to-agent communications:

- **Service providers** can require attestation before serving high-impact tools/data, reducing the risk of being blamed for harm caused by an unguarded or misconfigured agent.
- **Pro users** can verify that a remote agent is actually running under the controls it claims (not just configured that way), before delegating tasks or sharing sensitive context.
- **Data/IP owners** can enforce usage boundaries (e.g., “analyze but don’t exfiltrate”) of their assets.

This connects to our earlier work on [open-source agentic protocols and x402-extensions](https://github.com/SaharaLabsAI/x-function/tree/main/verifiable), where agents use verifiable checks so access to data/tools is granted only when policy conditions are met when making micro-payments powered by x402 protocol.

## System overview

**Disclaimer: this version of the demo is for demonstrative purposes only.**


We achieve verifiable guardrails by running it inside an AWS Nitro Enclave and using remote attestation to prove exactly what guardrail code is protecting the agent (a stable PCR2 measurement). All LLM traffic is forced through a FastAPI-based interception proxy (integrated with the guardrail); Verifiers can then check the attestation (PCRs plus embedded agent metadata/hashes) before trusting the agent or serving it data.

Please note the attestation cannot ensure the agent to be 100% “safe” (the guardrail code could still have vulnerabilities, and the LLM guardrail can make mistakes), but it ensures the promised guardrail code is actually running.

## Quickstart

1. Launch an AWS EC2 `m5.xlarge` instance with Nitro Enclave modules enabled.

2. Build the enclave image of the guardrail that protects the agent, which will run in the enclave later. 

```
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

# to clean-up
# nitro-cli terminate-enclave --enclave-id ${ENCLAVE_ID}

```


4. Launch all Vsock proxies and inject a version of the Clawdbot/Openclaw into the enclave. 

```
./ec2_setup.sh --agent-version 2026.1.24-3 --enclave-cid $ENCLAVE_CID --api-key ${OPENAI_API_KEY} 
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

**Caution.** To ensure the entire communication is untampered, end-to-end encryption between user and the agent running in the enclave is needed [(example)](https://github.com/SaharaLabsAI/x-function/tree/main/verifiable). This is not implemented yet in this demo.

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
