#!/usr/bin/env node
/**
 * Hancock AI Security Agent — Node.js Client
 * Backed by NVIDIA NIM (Qwen 2.5 Coder 32B + Mistral 7B)
 *
 * Usage:
 *   NVIDIA_API_KEY=nvapi-... node hancock.js
 *   NVIDIA_API_KEY=nvapi-... node hancock.js --mode code
 *   NVIDIA_API_KEY=nvapi-... node hancock.js --mode code --task "write a YARA rule for Emotet"
 */

import OpenAI from 'openai';
import readline from 'readline';

// ── Models ──────────────────────────────────────────────────────────────────
const MODELS = {
  'mistral-7b':    'mistralai/mistral-7b-instruct-v0.3',
  'qwen-coder':    'qwen/qwen2.5-coder-32b-instruct',
  'llama-8b':      'meta/llama-3.1-8b-instruct',
  'mixtral-8x7b':  'mistralai/mixtral-8x7b-instruct-v0.1',
};

const DEFAULT_MODEL  = process.env.HANCOCK_MODEL        || MODELS['mistral-7b'];
const CODER_MODEL    = process.env.HANCOCK_CODER_MODEL  || MODELS['qwen-coder'];

// ── System Prompts ──────────────────────────────────────────────────────────
const SECURITY_SYSTEM = `You are Hancock, an elite AI cybersecurity agent built by CyberViser.
Your expertise spans penetration testing, threat intelligence, SOC analysis, incident response,
CISO strategy, and security architecture. Respond with actionable, technically precise guidance.
Use MITRE ATT&CK framework, CVE data, and industry best practices. Be concise but thorough.`;

const CODE_SYSTEM = `You are Hancock Code, an elite security code specialist built by CyberViser.
You write production-quality security tools in Python, Bash, PowerShell, and Go.
Specialties: SIEM queries (KQL/SPL), YARA/Sigma rules, exploit PoCs, CTF scripts,
secure code review, IDS signatures, threat hunting queries. Always include comments.`;

const SIGMA_SYSTEM = `You are Hancock Sigma, CyberViser's expert detection engineer.
Write production-ready Sigma YAML rules with correct logsource, detection logic, MITRE ATT&CK tags,
falsepositives, and severity level. After the YAML, briefly explain what it detects and tuning notes.`;

const CISO_SYSTEM = `You are Hancock CISO, CyberViser's AI-powered Chief Information Security Officer advisor.
Expertise: NIST RMF, ISO 27001, SOC 2, PCI-DSS, HIPAA, GDPR, NIST CSF 2.0, CIS Controls v8.
Translate technical risk into business impact. Prioritize by likelihood × impact × cost.
Provide executive-ready language referencing specific control IDs where relevant.`;

const YARA_SYSTEM = `You are Hancock YARA, CyberViser's expert malware analyst.
Write production-ready YARA rules with meta, string patterns ($hex, $ascii, $regex, $wide),
and condition logic. Use pe/elf modules when appropriate.
After the rule, explain what it detects and list known false positive sources.`;

// ── NIM Client ──────────────────────────────────────────────────────────────
function createClient() {
  const apiKey = process.env.NVIDIA_API_KEY;
  if (!apiKey) {
    console.error('❌  Set NVIDIA_API_KEY env var first.\n   export NVIDIA_API_KEY=nvapi-...');
    process.exit(1);
  }
  return new OpenAI({
    apiKey,
    baseURL: 'https://integrate.api.nvidia.com/v1',
  });
}

// ── Ask ──────────────────────────────────────────────────────────────────────
async function ask(client, prompt, mode = 'security') {
  const isCode  = mode === 'code';
  const isSigma = mode === 'sigma';
  const isCiso  = mode === 'ciso';
  const isYara  = mode === 'yara';
  const model   = isCode ? CODER_MODEL : DEFAULT_MODEL;
  const system  = isCode ? CODE_SYSTEM : isSigma ? SIGMA_SYSTEM : isCiso ? CISO_SYSTEM : isYara ? YARA_SYSTEM : SECURITY_SYSTEM;
  const temp    = isCode || isSigma || isYara ? 0.2 : isCiso ? 0.3 : 0.7;
  const topP    = isCode || isSigma || isYara ? 0.7 : 0.95;
  const maxTok  = isCode || isSigma || isCiso || isYara ? 2048 : 1024;

  const completion = await client.chat.completions.create({
    model,
    messages: [
      { role: 'system',  content: system },
      { role: 'user',    content: prompt },
    ],
    temperature: temp,
    top_p:       topP,
    max_tokens:  maxTok,
    stream: false,
  });

  return {
    model,
    mode,
    answer: completion.choices[0]?.message?.content ?? '(no response)',
    usage:  completion.usage,
  };
}

// ── Stream Ask ────────────────────────────────────────────────────────────────
async function askStream(client, prompt, mode = 'security') {
  const isCode  = mode === 'code';
  const isSigma = mode === 'sigma';
  const isCiso  = mode === 'ciso';
  const isYara  = mode === 'yara';
  const model   = isCode ? CODER_MODEL : DEFAULT_MODEL;
  const system  = isCode ? CODE_SYSTEM : isSigma ? SIGMA_SYSTEM : isCiso ? CISO_SYSTEM : isYara ? YARA_SYSTEM : SECURITY_SYSTEM;
  const temp    = isCode || isSigma || isYara ? 0.2 : isCiso ? 0.3 : 0.7;
  const topP    = isCode || isSigma || isYara ? 0.7 : 0.95;
  const maxTok  = isCode || isSigma || isCiso || isYara ? 2048 : 1024;

  process.stdout.write('\nHancock > ');
  const stream = await client.chat.completions.create({
    model,
    messages: [
      { role: 'system',  content: system },
      { role: 'user',    content: prompt },
    ],
    temperature: temp,
    top_p:       topP,
    max_tokens:  maxTok,
    stream: true,
  });

  for await (const chunk of stream) {
    const text = chunk.choices[0]?.delta?.content ?? '';
    process.stdout.write(text);
  }
  process.stdout.write('\n\n');
}

// ── Interactive CLI ───────────────────────────────────────────────────────────
async function interactiveCLI(client, initialMode) {
  let mode = initialMode ?? 'security';

  console.log(`
╔══════════════════════════════════════════════════════════╗
║   HANCOCK  —  AI Cybersecurity Agent  (Node.js client)  ║
║   Powered by NVIDIA NIM + CyberViser                    ║
╚══════════════════════════════════════════════════════════╝
Mode: ${mode} | Model: ${mode === 'code' ? CODER_MODEL : DEFAULT_MODEL}

Commands: /mode security | /mode code | /mode sigma | /mode ciso | /mode yara | /model <alias> | /exit
Aliases:  mistral-7b | qwen-coder | llama-8b | mixtral-8x7b
`);

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const prompt = () => new Promise(resolve => rl.question(`[${mode}] > `, resolve));

  // eslint-disable-next-line no-constant-condition
  while (true) {
    const input = (await prompt()).trim();
    if (!input) continue;

    if (input === '/exit' || input === '/quit') { rl.close(); break; }

    if (input.startsWith('/mode ')) {
      mode = input.slice(6).trim();
      console.log(`Switched to ${mode} mode — model: ${mode === 'code' ? CODER_MODEL : DEFAULT_MODEL}\n`);
      continue;
    }

    if (input.startsWith('/model ')) {
      const alias = input.slice(7).trim();
      const resolved = MODELS[alias] ?? alias;
      process.env.HANCOCK_MODEL = resolved;
      console.log(`Model set to ${resolved}\n`);
      continue;
    }

    try {
      await askStream(client, input, mode);
    } catch (err) {
      console.error(`\n⚠️  API error: ${err.message}\n`);
    }
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  const args = process.argv.slice(2);
  const modeIdx = args.indexOf('--mode');
  const taskIdx = args.indexOf('--task');
  const mode    = modeIdx !== -1 ? args[modeIdx + 1] : 'security';
  const task    = taskIdx !== -1 ? args[taskIdx + 1] : null;

  const client = createClient();

  if (task) {
    // One-shot mode
    const result = await ask(client, task, mode);
    console.log(`\nModel: ${result.model} | Tokens: ${JSON.stringify(result.usage)}\n`);
    console.log(result.answer);
  } else {
    await interactiveCLI(client, mode);
  }
}

main().catch(err => { console.error(err); process.exit(1); });
