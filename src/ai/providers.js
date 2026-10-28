'use strict';

// Sağlayıcı-bağımsız sohbet katmanı. Harici SDK yok; doğrudan HTTPS (fetch).
// Dahili "normalize" mesaj biçimi tüm sağlayıcılara çevrilir, böylece ajan
// döngüsü tek bir biçimle çalışır.
//
// Normalize mesaj biçimi:
//   { role:'user',      content:[{type:'text', text}] }
//   { role:'assistant', content:[{type:'text', text}, {type:'tool_use', id, name, input}] }
//   { role:'tool',      toolCallId, name, content:'<string>' }
//
// tools: [{ name, description, schema:<JSON Schema object> }]
//
// chat(...) döndürür: { text, toolCalls:[{id,name,input}], stopReason, usage }

async function chat(opts) {
  const { provider } = opts;
  if (provider === 'anthropic') return chatAnthropic(opts);
  if (provider === 'openai') return chatOpenAI(opts);
  if (provider === 'gemini') return chatGemini(opts);
  throw new Error('Bilinmeyen sağlayıcı: ' + provider);
}

// --------------------------------------------------------------- Anthropic
async function chatAnthropic({ apiKey, model, system, messages, tools, maxTokens = 4096, signal }) {
  const body = {
    model,
    max_tokens: maxTokens,
    system,
    tools: (tools || []).map((t) => ({ name: t.name, description: t.description, input_schema: t.schema })),
    messages: messages.map(toAnthropicMsg)
  };
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    signal,
    headers: {
      'content-type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify(body)
  });
  const data = await res.json();
  if (!res.ok) throw apiError('Anthropic', res.status, data);

  const text = (data.content || [])
    .filter((b) => b.type === 'text')
    .map((b) => b.text)
    .join('\n')
    .trim();
  const toolCalls = (data.content || [])
    .filter((b) => b.type === 'tool_use')
    .map((b) => ({ id: b.id, name: b.name, input: b.input || {} }));
  return { text, toolCalls, stopReason: data.stop_reason, usage: data.usage };
}

function toAnthropicMsg(m) {
  if (m.role === 'tool') {
    return {
      role: 'user',
      content: [{ type: 'tool_result', tool_use_id: m.toolCallId, content: m.content }]
    };
  }
  const content = (m.content || []).map((c) => {
    if (c.type === 'text') return { type: 'text', text: c.text };
    if (c.type === 'tool_use') return { type: 'tool_use', id: c.id, name: c.name, input: c.input };
    return c;
  });
  return { role: m.role, content };
}

// ------------------------------------------------------------------ OpenAI
async function chatOpenAI({ apiKey, model, system, messages, tools, maxTokens = 4096, signal, baseUrl }) {
  const msgs = [];
  if (system) msgs.push({ role: 'system', content: system });
  for (const m of messages) msgs.push(toOpenAIMsg(m));

  const body = {
    model,
    max_tokens: maxTokens,
    messages: msgs,
    tools: (tools || []).map((t) => ({
      type: 'function',
      function: { name: t.name, description: t.description, parameters: t.schema }
    }))
  };
  const url = (baseUrl || 'https://api.openai.com/v1') + '/chat/completions';
  const res = await fetch(url, {
    method: 'POST',
    signal,
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + apiKey },
    body: JSON.stringify(body)
  });
  const data = await res.json();
  if (!res.ok) throw apiError('OpenAI', res.status, data);

  const msg = (data.choices && data.choices[0] && data.choices[0].message) || {};
  const text = (msg.content || '').trim();
  const toolCalls = (msg.tool_calls || []).map((tc) => ({
    id: tc.id,
    name: tc.function.name,
    input: safeJson(tc.function.arguments)
  }));
  return { text, toolCalls, stopReason: data.choices && data.choices[0] && data.choices[0].finish_reason };
}

function toOpenAIMsg(m) {
  if (m.role === 'tool') {
    return { role: 'tool', tool_call_id: m.toolCallId, content: m.content };
  }
  if (m.role === 'assistant') {
    const text = (m.content || []).filter((c) => c.type === 'text').map((c) => c.text).join('\n');
    const toolCalls = (m.content || [])
      .filter((c) => c.type === 'tool_use')
      .map((c) => ({ id: c.id, type: 'function', function: { name: c.name, arguments: JSON.stringify(c.input || {}) } }));
    const out = { role: 'assistant', content: text || null };
    if (toolCalls.length) out.tool_calls = toolCalls;
    return out;
  }
  // user
  const text = (m.content || []).filter((c) => c.type === 'text').map((c) => c.text).join('\n');
  return { role: 'user', content: text };
}

// ------------------------------------------------------------------ Gemini
async function chatGemini({ apiKey, model, system, messages, tools, signal }) {
  const contents = [];
  for (const m of messages) {
    if (m.role === 'tool') {
      contents.push({
        role: 'user',
        parts: [{ functionResponse: { name: m.name, response: { result: m.content } } }]
      });
    } else if (m.role === 'assistant') {
      const parts = [];
      for (const c of m.content || []) {
        if (c.type === 'text' && c.text) parts.push({ text: c.text });
        if (c.type === 'tool_use') {
          // Gemini 3: functionCall geri gönderilirken thoughtSignature zorunlu.
          const part = { functionCall: { name: c.name, args: c.input || {} } };
          if (c.thoughtSignature) part.thoughtSignature = c.thoughtSignature;
          parts.push(part);
        }
      }
      contents.push({ role: 'model', parts });
    } else {
      const text = (m.content || []).filter((c) => c.type === 'text').map((c) => c.text).join('\n');
      contents.push({ role: 'user', parts: [{ text }] });
    }
  }

  const body = {
    contents,
    systemInstruction: system ? { parts: [{ text: system }] } : undefined,
    tools: tools && tools.length
      ? [{ functionDeclarations: tools.map((t) => ({ name: t.name, description: t.description, parameters: toGeminiParams(t.schema) })) }]
      : undefined
  };
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;
  const res = await fetch(url, {
    method: 'POST',
    signal,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await res.json();
  if (!res.ok) throw apiError('Gemini', res.status, data);

  const cand = (data.candidates && data.candidates[0]) || {};
  const parts = (cand.content && cand.content.parts) || [];
  const text = parts.filter((p) => p.text).map((p) => p.text).join('\n').trim();
  let i = 0;
  const toolCalls = parts
    .filter((p) => p.functionCall)
    .map((p) => ({
      id: 'gem_' + i++,
      name: p.functionCall.name,
      input: p.functionCall.args || {},
      thoughtSignature: p.thoughtSignature // Gemini 3: geri gönderimde gerekli
    }));
  return { text, toolCalls, stopReason: cand.finishReason };
}

// ------------------------------------------------------------------ helpers
// Gemini, JSON Schema'nın bir alt kümesini (OpenAPI benzeri) kabul eder ve
// "additionalProperties", "$schema" gibi alanları REDDEDER. Şemayı ona göre temizle.
function stripGeminiUnsupported(schema) {
  if (Array.isArray(schema)) return schema.map(stripGeminiUnsupported);
  if (schema && typeof schema === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(schema)) {
      if (k === 'additionalProperties' || k === '$schema') continue;
      out[k] = stripGeminiUnsupported(v);
    }
    return out;
  }
  return schema;
}

// Parametresiz araçlarda (boş properties) Gemini'ye parameters hiç gönderme.
function toGeminiParams(schema) {
  const s = stripGeminiUnsupported(schema);
  if (s && s.type === 'object' && (!s.properties || Object.keys(s.properties).length === 0)) return undefined;
  return s;
}

function safeJson(s) {
  try {
    return JSON.parse(s);
  } catch {
    return {};
  }
}
function apiErr(name, status, data) {
  const msg = (data && (data.error && (data.error.message || data.error)) ) || JSON.stringify(data).slice(0, 300);
  return `${name} API hatası (${status}): ${msg}`;
}

// Geçici (yeniden denenebilir) sunucu hatalarını işaretli bir Error ile fırlat.
function apiError(name, status, data) {
  const e = new Error(apiErr(name, status, data));
  e.status = status;
  e.retryable = status === 429 || status === 500 || status === 502 || status === 503 || status === 529;
  return e;
}

// Önerilen varsayılan model ID'leri (kullanıcı arayüzde değiştirebilir).
const DEFAULT_MODELS = {
  anthropic: ['claude-sonnet-4-5', 'claude-opus-4-1', 'claude-3-5-haiku-latest'],
  openai: ['gpt-4o', 'gpt-4o-mini', 'o4-mini'],
  gemini: ['gemini-3-flash-preview', 'gemini-3.1-pro-preview']
};

module.exports = { chat, DEFAULT_MODELS };
