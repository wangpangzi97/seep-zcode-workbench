#!/usr/bin/env node
/**
 * Seep Lab 闸门 —— ZCode UserPromptSubmit hook
 *
 * 行为（对齐 seep 的 lab-gate.js）：
 *   - 默认关闭。只有当本次提示词里出现「lab：」「lab:」「实验：」「enter lab」
 *     这类**独立的开关指令**时，才把作战纪律注入上下文。
 *   - 提到 APK / 破解 / hook 等词不算激活 —— 这是刻意的安全边界。
 *   - 一旦激活，本会话后续提示都继续注入（会话作用域）。
 *
 * 输入：stdin 的 JSON（{ prompt, session_id, ... }）
 * 输出：stdout 的 JSON { "hookSpecificOutput": { "hookEventName": "UserPromptSubmit",
 *        "additionalContext": "..." } }
 *
 * 注：纪律正文不在每轮重复全量注入 —— 首次注入全文，之后只注入一小段提醒，
 * 避免长会话里上下文被反复撑爆。
 */
'use strict';

const { readFileSync, existsSync, mkdirSync, writeFileSync } = require('node:fs');
const { join, dirname } = require('node:path');
const { tmpdir, homedir } = require('node:os');

const PLUGIN_ROOT = process.env.ZCODE_PLUGIN_ROOT || process.env.CLAUDE_PLUGIN_ROOT || __dirname;

// ---------- 读取 stdin ----------
function readStdin() {
  try {
    return readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

// ---------- 开关指令识别 ----------
// 必须是「指令式」出现：整行/整句就是这个开关，而不是句子里顺带提到。
const ACTIVATE = /^\s*(lab\s*[:：]|实验\s*[:：]|enter\s+lab\s*$|进入实验\s*$)/i;
const DEACTIVATE = /^\s*(退出实验|exit\s+lab|end\s+lab|leave\s+lab)\s*$/i;

function detectIntent(prompt) {
  const text = String(prompt || '').trim();
  if (!text) return 'none';

  // 逐行看：任一行是纯开关指令即生效（用户可能先写一句再说别的）
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const t = line.trim();
    if (!t) continue;
    if (DEACTIVATE.test(t)) return 'off';
    if (ACTIVATE.test(t)) return 'on';
  }
  return 'none';
}

// ---------- 会话状态 ----------
function statePath(sessionId) {
  const base = process.env.ZCODE_PLUGIN_DATA
    || join(process.env.LOCALAPPDATA || tmpdir(), 'seep-zcode');
  const safe = String(sessionId || 'default').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80);
  return join(base, `lab-${safe}.json`);
}

function readState(sessionId) {
  const p = statePath(sessionId);
  try {
    if (!existsSync(p)) return { active: false, primed: false };
    return JSON.parse(readFileSync(p, 'utf8'));
  } catch {
    return { active: false, primed: false };
  }
}

function writeState(sessionId, state) {
  const p = statePath(sessionId);
  try {
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, JSON.stringify(state, null, 2), 'utf8');
  } catch {
    // 状态写不进去不该阻断会话
  }
}

// ---------- 纪律正文 ----------
function loadDiscipline() {
  const repoRoot = process.env.SEEP_ROOT || '';
  const candidates = [
    join(PLUGIN_ROOT, '..', 'discipline', 'SYSTEM.md'),
    repoRoot && join(repoRoot, 'Tool', 'prompts', 'SYSTEM.md'),
    join(homedir(), '.zcode', 'seep', 'SYSTEM.md'),
  ].filter(Boolean);

  for (const c of candidates) {
    try {
      if (existsSync(c)) {
        const body = readFileSync(c, 'utf8');
        if (body.trim()) return body;
      }
    } catch { /* 下一个 */ }
  }
  return '';
}

const REMINDER = [
  '【Seep Lab 作战模式 · 进行中】',
  '纪律要点：先 G-Auth 授权门 → 自动判型（平台 × 类型）→ 分发子能力 → 三段式报告。',
  '禁止绕过总控直接调子能力；门禁命名必须带层前缀（AUTH-G* / APK-G* / EXE-G*）。',
  '完整纪律见本会话首轮注入的 SYSTEM.md。'
].join('\n');

// ---------- 主流程 ----------
function main() {
  let payload = {};
  try {
    payload = JSON.parse(readStdin() || '{}');
  } catch {
    payload = {};
  }

  const prompt = payload.prompt ?? payload.user_prompt ?? payload.text ?? '';
  const sessionId = payload.session_id ?? payload.sessionId ?? 'default';

  const intent = detectIntent(prompt);
  const state = readState(sessionId);

  if (intent === 'off') {
    writeState(sessionId, { active: false, primed: false });
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'UserPromptSubmit',
        additionalContext: '【Seep Lab 已退出作战模式】'
      }
    }));
    return;
  }

  if (intent === 'on') {
    const discipline = loadDiscipline();
    const active = { active: true, primed: true };
    writeState(sessionId, active);

    const body = discipline
      ? '【Seep Lab 作战模式 · 已激活】以下是本工作台纪律正文：\n\n' + discipline
      : REMINDER + '\n\n（未找到 SYSTEM.md，请检查 SEEP_ROOT 或插件 discipline/ 目录）';

    process.stdout.write(JSON.stringify({
      hookSpecificOutput: { hookEventName: 'UserPromptSubmit', additionalContext: body }
    }));
    return;
  }

  // 未给出开关指令：若本会话已激活，则继续注入简短提醒
  if (state.active) {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: { hookEventName: 'UserPromptSubmit', additionalContext: REMINDER }
    }));
    return;
  }

  // 默认：什么都不做，也不输出（空输出合法）
}

main();
