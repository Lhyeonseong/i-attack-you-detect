-- D11 출처 seed (ADR-S4-02 D11) — 커밋된 증거 로그에 있는 스택 버전만 INSERT.
-- 실행: validation_rw(소유자). append-only(잘못 넣으면 못 지움) → db.sh 의 git diff 게이트 통과 후에만 적용.
-- 재실행 안전: uq_run_provenance (run_id,item,source_file,COALESCE(source_line,-1)) + ON CONFLICT DO NOTHING.
--
-- 적격성(S4-6 결정 B, /tmp/s4-6-provenance-diff.log 로 검증):
--   · b1c26be1(S4-STACK-6-BASELINE, commit e3b5f52): 전용 줄 2026-10-21_s6-baseline.log:2.
--   · 805f3b8e·2ad849e0·3818e21a·7fc9767f: e3b5f52 대비 docker-compose.yml·.env.example·build.gradle 의
--       이미지 digest 줄·Boot 버전 줄 변경 0 (caldera 는 8b93151 대비 digest 변경 0) → 공용 줄 + stack_basis.
--   · 변경 있는 run 은 넣지 않음(화면 "기록 없음"). 현재 4개 모두 변경 0 확인됨.
SET search_path = validation;

-- ── b1c26be1 (기준 run): 전용 줄 s6-baseline.log:2 (caldera 는 caldera-pin.log:2) ──
INSERT INTO run_provenance_note (run_id, item, value, source_file, source_line)
SELECT mr.run_id, x.item, x.value, x.source_file, x.source_line
FROM (VALUES
  ('suricata',   '8.0.7',  'detections/measurements/evidence/2026-10-21_s6-baseline.log', 2),
  ('wazuh',      '4.14.9', 'detections/measurements/evidence/2026-10-21_s6-baseline.log', 2),
  ('postgresql', '16.15',  'detections/measurements/evidence/2026-10-21_s6-baseline.log', 2),
  ('spring_boot','4.1.1',  'detections/measurements/evidence/2026-10-21_s6-baseline.log', 2),
  ('caldera',    '5.2.0',  'detections/measurements/evidence/2026-10-20_4-caldera-pin.log', 2)
) AS x(item, value, source_file, source_line)
JOIN measurement_run mr ON mr.label = 'S4-STACK-6-BASELINE'
ON CONFLICT (run_id, item, source_file, COALESCE(source_line, -1)) DO NOTHING;

-- ── 적격 run 4개: 공용 줄(reboot-verify.log:2) + caldera-pin.log:2 ──
INSERT INTO run_provenance_note (run_id, item, value, source_file, source_line)
SELECT mr.run_id, x.item, x.value, x.source_file, x.source_line
FROM (VALUES
  ('suricata',   '8.0.7',  'detections/measurements/evidence/2026-10-21_reboot-verify.log', 2),
  ('wazuh',      '4.14.9', 'detections/measurements/evidence/2026-10-21_reboot-verify.log', 2),
  ('postgresql', '16.15',  'detections/measurements/evidence/2026-10-21_reboot-verify.log', 2),
  ('spring_boot','4.1.1',  'detections/measurements/evidence/2026-10-21_reboot-verify.log', 2),
  ('caldera',    '5.2.0',  'detections/measurements/evidence/2026-10-20_4-caldera-pin.log', 2)
) AS x(item, value, source_file, source_line)
CROSS JOIN (VALUES
  ('S5-SQLI-AFTER'), ('S5-SQLI-AFTER-BENIGN-WEB'), ('S4-5-BENIGN-WEB-R2'), ('S4-5-BENIGN-LOGIN')
) AS l(label)
JOIN measurement_run mr ON mr.label = l.label
ON CONFLICT (run_id, item, source_file, COALESCE(source_line, -1)) DO NOTHING;

-- ── 적격 run 4개: stack_basis 1행(공용 줄 사용 근거 = git diff 증거) ──
INSERT INTO run_provenance_note (run_id, item, value, source_file, source_line)
SELECT mr.run_id, 'stack_basis',
       'digest-pinned images & Boot unchanged since e3b5f52 (caldera since 8b93151)',
       'detections/measurements/evidence/2026-10-22_s4-6-provenance-diff.log', NULL
FROM measurement_run mr
WHERE mr.label IN ('S5-SQLI-AFTER','S5-SQLI-AFTER-BENIGN-WEB','S4-5-BENIGN-WEB-R2','S4-5-BENIGN-LOGIN')
ON CONFLICT (run_id, item, source_file, COALESCE(source_line, -1)) DO NOTHING;

-- 확인: run 라벨별 행수 (b1c26be1=5, 나머지 4개=6 → 합계 29)
SELECT r.label, count(*) notes
FROM run_provenance_note n JOIN measurement_run r USING(run_id)
GROUP BY r.label ORDER BY r.label;
