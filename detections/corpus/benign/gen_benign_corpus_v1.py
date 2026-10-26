#!/usr/bin/env python3
"""benign-corpus-v1 생성기 (ADR-S4-01 v1.8 R17·R18, S4-5-BENIGN-WEB).

근거는 엔드포인트 기능 명세(컨트롤러 코드)뿐이다. 탐지 룰·기존 negative-test 정의는 참조하지 않는다(순환 검증 방지).
  - ProductController.search   GET /api/products/search?keyword=<상품명 검색어>  (products.name LIKE 검색)
  - FileController.download    GET /api/files/download?filename=<업로드 문서 파일명>
  - PreviewController.preview  GET /api/preview?url=<http/https 공개 웹 URL>
생성 규칙은 아래 각 함수의 문서 문자열. random.Random(SEED) 고정 → 같은 Python 3 에서 같은 출력.
사용: python3 -I gen_benign_corpus_v1.py > benign-corpus-v1.yaml
"""
import hashlib
import random

SEED = 20261022
PER_ENDPOINT = 320
# ADR 회귀 세트 문자열은 코퍼스에 넣지 않는다(정상 코퍼스(M14) 규칙)
EXCLUDED = ("laptop--pro", "report.pdf")


def search_terms(rng):
    """상품 카탈로그 검색어: 영문·한글 상품군, 브랜드·모델명, 숫자·용량·크기, 공백 포함 조합."""
    en = ["laptop", "smartphone", "tablet", "headphone", "monitor", "keyboard", "mouse", "charger",
          "speaker", "camera", "smartwatch", "earbuds", "router", "printer", "webcam", "microphone",
          "power bank", "usb hub", "ssd", "memory card"]
    ko = ["노트북", "스마트폰", "태블릿", "헤드폰", "모니터", "키보드", "마우스", "충전기", "스피커",
          "카메라", "스마트워치", "이어폰", "공유기", "프린터", "보조배터리", "케이스", "보호필름", "거치대"]
    brands = ["galaxy", "iphone", "pixel", "thinkpad", "macbook", "gram", "zenbook", "surface",
              "ipad", "xperia", "airpods", "buds", "vivobook", "ideapad", "pavilion"]
    models = ["s24", "15 pro", "8a", "x1 carbon", "air m3", "16", "14 oled", "pro 9", "mini 6",
              "1 v", "pro 2", "fe", "go 3", "slim 5", "plus"]
    qualifiers = ["128gb", "256gb", "512gb", "1tb", "13인치", "15인치", "27인치", "블랙", "실버",
                  "화이트", "무선", "블루투스", "4k", "2025", "중고", "정품", "케이스 포함"]
    out = set()
    pool = []
    pool += en + ko
    for b in brands:
        for m in models:
            pool.append(f"{b} {m}")
    for base in en + ko:
        for q in qualifiers:
            pool.append(f"{base} {q}")
    rng.shuffle(pool)
    for term in pool:
        if len(out) >= PER_ENDPOINT:
            break
        out.add(term)
    return sorted(out)


def download_names(rng):
    """업로드 문서 형태 파일명: 업무 문서 이름 + 날짜·버전·부서, 확장자 다양(pdf·docx·xlsx·pptx·txt·csv·png·jpg·zip·hwp)."""
    stems = ["manual", "brochure", "price-list", "catalog", "invoice", "quotation", "contract",
             "meeting-notes", "user-guide", "release-notes", "spec-sheet", "warranty", "receipt",
             "shipping-label", "product-photo", "banner", "presentation", "budget", "schedule", "survey",
             "제품설명서", "견적서", "회의록", "사용설명서", "계약서"]
    tags = ["2024", "2025", "2026-q1", "2026-q2", "v1", "v2", "v3", "final", "draft", "kr", "en",
            "sales", "support", "hr", "marketing", "jan", "feb", "mar"]
    exts = ["pdf", "docx", "xlsx", "pptx", "txt", "csv", "png", "jpg", "zip", "hwp"]
    pool = [f"{s}_{t}.{e}" for s in stems for t in tags for e in exts]
    rng.shuffle(pool)
    out = [n for n in pool if not any(x in n for x in EXCLUDED)][:PER_ENDPOINT]
    return sorted(out)


def preview_urls(rng):
    """공개 웹 URL(http/https): 여러 공개 사이트의 문서·기사·상품 페이지 경로, 도메인당 소수 건으로 분산."""
    sites = ["https://www.wikipedia.org", "https://en.wikipedia.org", "https://ko.wikipedia.org",
             "https://developer.mozilla.org", "https://docs.python.org", "https://www.w3.org",
             "https://www.iana.org", "https://www.ietf.org", "https://www.rfc-editor.org",
             "https://github.com", "https://gitlab.com", "https://stackoverflow.com",
             "https://www.naver.com", "https://news.naver.com", "https://www.daum.net",
             "https://www.youtube.com", "https://www.bbc.com", "https://www.reuters.com",
             "https://www.nytimes.com", "https://www.theguardian.com", "https://www.apple.com",
             "https://www.samsung.com", "https://www.lg.com", "https://www.microsoft.com",
             "https://www.amazon.com", "https://www.coupang.com", "https://www.11st.co.kr",
             "https://www.gmarket.co.kr", "https://www.oracle.com", "https://www.postgresql.org",
             "https://spring.io", "https://kotlinlang.org", "https://www.rust-lang.org", "https://go.dev",
             "http://example.com", "http://example.org", "http://example.net", "https://www.gnu.org",
             "https://www.kernel.org", "https://www.debian.org"]
    paths = ["/", "/about", "/help", "/news", "/blog", "/docs", "/products", "/support", "/contact",
             "/images/logo.png", "/assets/banner.jpg", "/en/latest/", "/ko/", "/search?q=laptop",
             "/search?q=tablet", "/wiki/Main_Page", "/articles/2025/review", "/shop/item?id=1024",
             "/downloads", "/faq", "/terms", "/privacy", "/sitemap.xml", "/rss"]
    pool = [s + p for s in sites for p in paths]
    rng.shuffle(pool)
    out = pool[:PER_ENDPOINT]
    return sorted(out)


def yq(s):
    """YAML 큰따옴표 문자열 (역슬래시·큰따옴표만 이스케이프 — 값에는 제어문자가 없다)."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    rng = random.Random(SEED)
    items = ([("/api/products/search", "keyword", v) for v in search_terms(rng)]
             + [("/api/files/download", "filename", v) for v in download_names(rng)]
             + [("/api/preview", "url", v) for v in preview_urls(rng)])
    rng.shuffle(items)  # 엔드포인트를 섞어 순차 전송(정상 사용자가 여러 기능을 오가는 모양)
    canonical = "".join(f"{i}\t{e}\t{p}\t{v}\n" for i, (e, p, v) in enumerate(items, 1))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    print("# benign-corpus-v1 — S4-5-BENIGN-WEB 정상 코퍼스 (ADR-S4-01 v1.8 R17·R18). 라벨 BENIGN 은 이 manifest 에만 둔다(B안).")
    print("# 생성 근거(기능 명세만, 탐지 룰·negative-test 정의 미참조):")
    print("#   ProductController.search  GET /api/products/search?keyword=  — products.name LIKE 검색 → 상품 카탈로그 검색어")
    print("#   FileController.download   GET /api/files/download?filename=  — 업로드 폴더의 파일 → 문서 형태 파일명")
    print("#   PreviewController.preview GET /api/preview?url=  — http/https 만 허용 → 공개 웹 URL")
    print(f"# 생성 규칙: gen_benign_corpus_v1.py, random.Random({SEED}), 엔드포인트별 {PER_ENDPOINT}건(값 중복 없음), 엔드포인트를 섞은 순차 순서.")
    print(f"#   제외 문자열(ADR 회귀 세트): {', '.join(EXCLUDED)}. login 은 별도 run(S4-5 범위 안, 별도 작업).")
    print("# items_sha256 = sha256(UTF-8, 각 항목 'seq<TAB>endpoint<TAB>param<TAB>value<LF>' 를 seq 순으로 이어 붙인 것)")
    print("corpus: benign-corpus-v1")
    print("label: BENIGN")
    print(f"items_sha256: {digest}")
    print("items:")
    for i, (e, p, v) in enumerate(items, 1):
        print(f"  - {{seq: {i}, endpoint: {e}, param: {p}, value: {yq(v)}}}")


if __name__ == "__main__":
    main()
