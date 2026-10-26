#!/usr/bin/env python3
"""login-plan-v1 생성기 (ADR-S4-01 v2.0 R17 f·R18 j, S4-5-BENIGN-LOGIN).

정상 로그인 요청 계획만 만든다 — 전송은 코드가 하지 않고 사람이 터미널 스크립트로 실행한다(§T).
비밀번호는 이 파일에 없다(CWE-798): credential_ref 별칭만 두고, 측정 시 BENIGN_CRED_<REF> 환경변수로 주입한다.
  - AuthController  POST /api/auth/login  요청 바디 {username, password}(추정 — §T 전송 전 확인), 엔드포인트 /api/auth/login
열: seq,credential_ref,username,scenario(NORMAL|TYPO)
  - scenario 는 전송자 스크립트가 정상/오타를 정하는 메타. TYPO 는 전송 시점에 정상 비밀번호를 결정적으로 변형(파일·로그·DB 에 안 남김).
  - 정상 사용자도 오타를 낸다(Chatterjee et al. S&P 2016 MTurk 데스크톱 오타율 약 4.5% — 옮겨치기 조건이라 실제보다 높을 수 있음; 참고 Keith 2.2%).
    TYPO 비율 약 4.5%, 각 TYPO 행 바로 뒤에 같은 계정 NORMAL(오타 후 재시도). 오타 1~2회는 임계 10에 못 미쳐 상관 FP 가 아니어야 정상.
계정은 round-robin. 기본 user1(credential_ref=SEED_USER1). 추가 계정은 인자로 (별칭:username) 쌍을 준다.
random.Random(SEED) 고정 → 같은 Python 3 에서 같은 출력.
사용: python3 -I gen_login_plan_v1.py > login-plan-v1.csv
      python3 -I gen_login_plan_v1.py SEED_USER2:user2 SEED_USER3:user3 > login-plan-v1.csv
"""
import random
import sys

SEED = 20261022
ROWS = 300
TYPO_RATE = 0.045


def accounts(argv):
    """기본 user1 1개. 인자가 있으면 (credential_ref:username) 쌍을 순서대로 추가."""
    out = [("SEED_USER1", "user1")]
    for a in argv:
        ref, _, user = a.partition(":")
        if not ref or not user:
            raise SystemExit(f"계정 인자는 REF:username 형식: {a}")
        out.append((ref.strip(), user.strip()))
    return out


def plan(rng, accts):
    """round-robin 계정 순환. TYPO 를 약 TYPO_RATE 로 섞되, TYPO 바로 뒤는 같은 계정 NORMAL(재시도)."""
    n_typo = round(ROWS * TYPO_RATE)
    # TYPO 위치: 마지막 행은 재시도 NORMAL 자리를 위해 피한다
    typo_at = set(rng.sample(range(0, ROWS - 1), n_typo))
    rows = []
    i = 0
    acc = 0
    while len(rows) < ROWS:
        ref, user = accts[acc % len(accts)]
        if i in typo_at and len(rows) < ROWS - 1:
            rows.append((ref, user, "TYPO"))
            rows.append((ref, user, "NORMAL"))  # 같은 계정 재시도
        else:
            rows.append((ref, user, "NORMAL"))
        acc += 1
        i += 1
    return rows[:ROWS]


def main():
    rng = random.Random(SEED)
    accts = accounts(sys.argv[1:])
    rows = plan(rng, accts)
    print("# login-plan-v1 — S4-5-BENIGN-LOGIN 정상 로그인 계획 (ADR-S4-01 v2.0 R17 f·R18 j). 비밀번호 없음(CWE-798).")
    print("# 전송은 사람이 /tmp 스크립트로 실행(§T), 결과 CSV(seq,sent_at_ms,responded_at_ms,status)를 ingest 한다.")
    print("# 비밀번호는 측정 시 BENIGN_CRED_<credential_ref> 환경변수로 주입. TYPO 는 전송 시점에 정상 비번을 변형(파일에 안 남김).")
    print(f"# 생성: gen_login_plan_v1.py, random.Random({SEED}), {ROWS}행, TYPO 약 {TYPO_RATE:.1%}(각 TYPO 뒤 같은 계정 NORMAL).")
    print("seq,credential_ref,username,scenario")
    for seq, (ref, user, scenario) in enumerate(rows, start=1):
        print(f"{seq},{ref},{user},{scenario}")


if __name__ == "__main__":
    main()
