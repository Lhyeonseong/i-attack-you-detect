// S4-6 대시보드 캡처 + 접근성/금지문자열 검사 (ADR-S4-04 R-j, 지시서 Step 6).
// 세션 로그인(폼 UI 자동화 아님: GET /login→_csrf→POST /login), 확정(스냅샷) 값만. 1440×900 dsf2.
// 실행: Playwright 컨테이너에서 `node capture/capture.mjs` (capture.sh).
// 환경변수: BASE_URL, UI_USER, UI_PW(평문, 세션 로그인용), OUT_DIR(저장 경로, repo 상대), RUN_LABEL.
import { chromium } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';

const BASE = process.env.BASE_URL || 'https://127.0.0.1:8090';
const USER = process.env.UI_USER || 'viewer';
const PW = process.env.UI_PW || '';
const OUT = process.env.OUT_DIR || 'docs/report/img/dashboard';
const RUN_LABEL = process.env.RUN_LABEL || 'after';
mkdirSync(OUT, { recursive: true });

const problems = [];           // 치명(접근성·금지문자열·콘솔·CSP) → 종료코드
const manifest = [];           // 캡처 파일 목록 + sha256
const FORBIDDEN = ['[실측]'];  // 화면에 남으면 안 되는 문자열
const RUN_RE = /\bRun\b/;      // 용어: "Run" 단독 금지("측정"으로)
const CONSOLE_ERRS = [];       // 콘솔 error·CSP 위반(페이지 단위 1회 등록, 화면별로 슬라이스)

// 화면별 "데이터 로드 완료" 조건(in-page). 이 조건이 참이 된 뒤에 스크린샷.
// 재부팅 직후엔 DashboardContext 가 meta→runs→runDetail 을 연쇄 조회한 뒤에야
// runIds.after 가 채워지고, 각 화면이 그 id 로 다시 조회한다 — 레이아웃 래퍼
// (data-testid)만 기다리면 빈 표/"기록 없음" 상태에서 찍힌다(S4-6 재부팅 후 누락 원인).
const READY = {
  attacks: () => !!document.querySelector('a[href^="/attempts/"]'),  // 시도 목록 테이블 렌더
  detection: () => !!document.querySelector('.rb'),                  // 오탐 표 RatioBlock 렌더(benign 스냅샷 로드); 셀은 status 에 따라 rb-ratio/rb-not-valid
  revalidate: () => { const el = document.querySelector('.hero-v'); return !!el && !/기록 없음/.test(el.textContent || ''); },
  detail: () => !!document.querySelector('.banner h2'),              // 상세 배너(attempts 로드) 렌더
};

// 사이드바 라우트(순서 = 캡처 번호). detail 은 attacks 에서 진입.
const SCREENS = [
  ['overview', '/overview'], ['attacks', '/attacks'], ['detection', '/detection'],
  ['attck', '/attck'], ['system', '/system'], ['revalidate', '/revalidate'], ['report', '/report'],
];

function sha256(path) { return createHash('sha256').update(readFileSync(path)).digest('hex'); }
// 캡처 번호: SCREENS 순서(1~7), detail 은 attacks 진입분이라 목록 밖 → 8.
function numOf(id) { const i = SCREENS.findIndex((s) => s[0] === id); return String(i >= 0 ? i + 1 : 8).padStart(2, '0'); }

async function sessionLogin(ctx) {
  const g = await ctx.request.get(`${BASE}/login`);
  const html = await g.text();
  const m = html.match(/name="_csrf" value="([^"]+)"/);
  if (!m) throw new Error('로그인 페이지에서 _csrf 토큰을 못 찾음');
  const r = await ctx.request.post(`${BASE}/login`, {
    form: { username: USER, password: PW, _csrf: m[1] }, maxRedirects: 0,
  });
  // 성공 시 302 → /, 실패 시 302 → /login?error
  const loc = r.headers()['location'] || '';
  if (r.status() !== 302 || /\/login/.test(loc)) throw new Error(`세션 로그인 실패(status=${r.status()} loc=${loc})`);
}

async function checkScreen(page, id) {
  // 콘솔 오류·CSP 위반: 페이지 단위로 1회만 등록(main)하고, 여기선 이 화면 구간만 슬라이스
  const errStart = CONSOLE_ERRS.length;
  await page.waitForSelector(`[data-testid="screen-${id}"]`, { timeout: 15000 });
  await page.waitForLoadState('networkidle').catch(() => {});
  // 데이터 연쇄 조회(DashboardContext → 화면) 대기: ready 조건 충족 후 캡처.
  // 미충족이면 problem 으로 반드시 기록하고, 진단용으로 스크린샷은 계속 진행한다.
  if (READY[id]) {
    await page.waitForFunction(READY[id], null, { timeout: 15000 })
      .catch(() => problems.push(`${id}: 데이터 미로드(ready 조건 15s 미충족) — 빈 화면 의심`));
  }
  await page.waitForLoadState('networkidle').catch(() => {});
  await page.waitForTimeout(600); // 차트 렌더 여유

  // 금지 문자열
  const bodyText = await page.locator('body').innerText();
  for (const s of FORBIDDEN) if (bodyText.includes(s)) problems.push(`${id}: 금지문자열 "${s}"`);
  if (RUN_RE.test(bodyText)) problems.push(`${id}: 용어 "Run" 노출(→"측정")`);
  // "%" 단독(= 숫자%만 있고 'x건 중 y건'·'95% 범위' 보조문구 없는 엘리먼트) 휴리스틱.
  const pctAlone = await page.evaluate(() => {
    const re = /^\s*\d+(?:\.\d+)?\s*%\s*$/;
    const hasAux = (t) => t.includes('건 중') || t.includes('95% 범위');
    let bad = 0;
    for (const el of Array.from(document.querySelectorAll('*'))) {
      if (el.children.length !== 0 || !re.test(el.textContent || '')) continue;
      // R-b: "%" 는 'x건 중 y건' 또는 '95% 범위' 보조문구와 짝이어야 한다.
      // 보조문구는 형제·상위에 있으므로(RatioBlock 의 .rb-primary↔.rb-aux,
      // 도넛 <text>↔하단 .foot 등) 자기 자신이 아니라 상위 4단계까지 올라가며 찾는다.
      let p = el.parentElement, found = false;
      for (let up = 0; up < 4 && p; up++, p = p.parentElement) {
        if (hasAux(p.textContent || '')) { found = true; break; }
      }
      if (!found) bad++;
    }
    return bad;
  });
  if (pctAlone > 0) problems.push(`${id}: "%" 단독 표기 ${pctAlone}건`);

  // 접근성(axe) WCAG 2.2 AA
  const axe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
  if (axe.violations.length) {
    for (const v of axe.violations) problems.push(`${id}: axe ${v.id}(${v.impact}) x${v.nodes.length}`);
  }
  const errs = CONSOLE_ERRS.slice(errStart);
  if (errs.length) problems.push(`${id}: 콘솔/CSP 오류 ${errs.length}건 (${errs[0]?.slice(0, 120)})`);

  // 캡처: 전체 + 차트 요소 단독
  const num = numOf(id);
  const full = `${OUT}/${num}_${id}_${RUN_LABEL}.png`;
  await page.screenshot({ path: full, fullPage: true });
  manifest.push({ file: full, sha256: sha256(full) });
  const charts = page.locator('[role="img"], .donut, svg.chart, .vega-embed');
  const n = await charts.count();
  for (let i = 0; i < n && i < 6; i++) {
    const cf = `${OUT}/${num}_${id}_${RUN_LABEL}_chart${i}.png`;
    await charts.nth(i).screenshot({ path: cf }).then(() => manifest.push({ file: cf, sha256: sha256(cf) })).catch(() => {});
  }
}

const browser = await chromium.launch();
const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
try {
  await sessionLogin(ctx);
  const page = await ctx.newPage();
  // 콘솔 error·CSP 위반은 페이지 단위로 1회만 등록(이전 구현의 화면마다 리스너 누적 제거)
  page.on('console', (msg) => {
    const t = msg.text();
    if (msg.type() === 'error' || /Content Security Policy|unsafe-eval/i.test(t)) CONSOLE_ERRS.push(t);
  });
  await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('[data-testid^="screen-"]', { timeout: 15000 });
  for (const [id, route] of SCREENS) {
    // 클라이언트 네비게이션(사이드바 링크) — 서버 딥링크(미구현 fallback) 회피
    const link = page.locator(`a[href="${route}"]`).first();
    if (await link.count()) await link.click(); else await page.goto(`${BASE}${route}`, { waitUntil: 'domcontentloaded' });
    await checkScreen(page, id).catch((e) => problems.push(`${id}: 캡처 실패 ${e.message}`));
  }
  // detail: 사이드바 링크(클라이언트 네비 — 컨텍스트 warm 유지)로 attacks 재진입 →
  // 테이블 데이터 로드(READY.attacks)까지 기다린 뒤 첫 시도 링크로 진입.
  // (cold goto 는 DashboardContext 를 처음부터 재조회 → 15s 안에 행이 안 떠 링크 0 = detail 누락 원인)
  const atkLink = page.locator('a[href="/attacks"]').first();
  if (await atkLink.count()) await atkLink.click();
  else await page.goto(`${BASE}/attacks`, { waitUntil: 'domcontentloaded' }).catch(() => {});
  await page.waitForSelector('[data-testid="screen-attacks"]', { timeout: 15000 }).catch(() => {});
  await page.waitForFunction(READY.attacks, null, { timeout: 15000 }).catch(() => {});
  const dl = page.locator('a[href^="/attempts/"]').first();
  if (await dl.count()) {
    await dl.click();
    await checkScreen(page, 'detail').catch((e) => problems.push(`detail: 캡처 실패 ${e.message}`));
  } else {
    problems.push('detail: /attempts/ 링크 없음 → 상세 캡처 건너뜀(시도 데이터 미로드 의심)');
  }
} finally {
  writeFileSync(`${OUT}/_manifest.json`, JSON.stringify({ base: BASE, runLabel: RUN_LABEL, files: manifest }, null, 2));
  // 실패를 반드시 아티팩트로 남긴다(러너가 _evidence.txt 에 이어 붙임) — 조용한 누락 방지
  writeFileSync(`${OUT}/_problems.txt`,
    `capture problems=${problems.length} manifest=${manifest.length} base=${BASE} runLabel=${RUN_LABEL}\n`
    + problems.map((p) => 'PROBLEM ' + p).join('\n') + (problems.length ? '\n' : ''));
  await browser.close();
}

console.log(`## capture: ${manifest.length} files, problems=${problems.length}`);
for (const p of problems) console.log('PROBLEM ' + p);
process.exit(problems.length ? 1 : 0);
