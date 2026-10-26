#!/bin/sh
set -e
TMPL=/usr/src/app/conf/local.yml.template
OUT=/usr/src/app/conf/local.yml
: "${CALDERA_API_KEY_RED:?missing}"; : "${CALDERA_API_KEY_BLUE:?missing}"
: "${CALDERA_CRYPT_SALT:?missing}"; : "${CALDERA_ENCRYPTION_KEY:?missing}"
sed -e "s|\${CALDERA_API_KEY_RED}|${CALDERA_API_KEY_RED}|g" \
    -e "s|\${CALDERA_API_KEY_BLUE}|${CALDERA_API_KEY_BLUE}|g" \
    -e "s|\${CALDERA_CRYPT_SALT}|${CALDERA_CRYPT_SALT}|g" \
    -e "s|\${CALDERA_ENCRYPTION_KEY}|${CALDERA_ENCRYPTION_KEY}|g" \
    "$TMPL" > "$OUT"
# agents 설정은 git 템플릿이 원본(bootstrap_abilities: [] — 호스트 로그 삭제 ability 자동 실행 방지).
# Caldera 가 종료 때 conf/agents.yml 을 다시 써도 기동마다 덮어쓴다. 템플릿이 없으면 set -e 로 기동 실패
cp /usr/src/app/conf/agents.yml.template /usr/src/app/conf/agents.yml
exec python3 server.py
