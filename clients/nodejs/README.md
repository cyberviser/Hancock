# Hancock Node.js Client

Interact with Hancock's AI security platform from Node.js. Supports multiple LLM backends.

## Setup

```bash
cd clients/nodejs
npm install
```

Set one backend API key:

```bash
export HANCOCK_LLM_BACKEND=groq    && export GROQ_API_KEY=gsk_xxx        # Free 14,400 req/day
export HANCOCK_LLM_BACKEND=nvidia  && export NVIDIA_API_KEY=nvapi-xxx     # Free 1,000 req/day
export HANCOCK_LLM_BACKEND=together && export TOGETHER_API_KEY=xxx        # Free credits
export HANCOCK_LLM_BACKEND=openrouter && export OPENROUTER_API_KEY=xxx    # Free rotating models
export HANCOCK_LLM_BACKEND=ollama                                         # Local, no key needed
```

## Usage

### Interactive CLI
```bash
node hancock.js                    # security mode (Mistral 7B)
node hancock.js --mode code        # code mode (Qwen 2.5 Coder 32B)
```

### One-shot
```bash
node hancock.js --task "explain Log4Shell CVE-2021-44228"
node hancock.js --mode code --task "write a YARA rule for Emotet"
```

### In-session commands
```
/mode security    Switch to security analyst mode
/mode code        Switch to code generation mode  
/model qwen-coder Change model by alias
/exit             Quit
```

## Models

| Alias | Model |
|-------|-------|
| `mistral-7b` | mistralai/mistral-7b-instruct-v0.3 |
| `qwen-coder` | qwen/qwen2.5-coder-32b-instruct |
| `llama-8b` | meta/llama-3.1-8b-instruct |
| `mixtral-8x7b` | mistralai/mixtral-8x7b-instruct-v0.1 |

## Environment Variables

| Var | Default |
|-----|---------|
| `HANCOCK_LLM_BACKEND` | `nvidia` |
| `NVIDIA_API_KEY` | *(required for nvidia backend)* |
| `GROQ_API_KEY` | *(required for groq backend)* |
| `TOGETHER_API_KEY` | *(required for together backend)* |
| `OPENROUTER_API_KEY` | *(required for openrouter backend)* |
| `HANCOCK_MODEL` | mistralai/mistral-7b-instruct-v0.3 |
| `HANCOCK_CODER_MODEL` | qwen/qwen2.5-coder-32b-instruct |
