// 운영 빌드는 실제 fetch(httpClient), 개발(import.meta.env.DEV)은 mock.
import type { ApiClient } from './types';
import { httpClient } from './client';

let _client: ApiClient = httpClient;
let _runIds = { after: '', before: '', benignWeb: '', benignLogin: '' };

if (import.meta.env.DEV) {
  // 동적 import 로 운영 번들에서 mock 제외(트리 셰이킹).
  const mod = await import('./mock');
  _client = mod.mockClient;
  _runIds = mod.RUN_IDS;
}

export const api: ApiClient = _client;
/** 개발 모드에서 알려진 run id. 운영에서는 /runs 로 조회. */
export const KNOWN_RUN_IDS = _runIds;
export * from './types';
