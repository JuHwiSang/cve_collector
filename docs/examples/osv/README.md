# OSV API 예시 데이터

OSV.dev에서 가져온 실제 취약점 데이터 예시들입니다.

## 파일 목록

### ZIP 다운로드에서 추출한 파일
- `vulnerability-from-zip-download.json` - ZIP에서 추출한 GHSA 파일 (linux-cmdline 패키지)

### API 응답 데이터  
- `single-vulnerability-api-response.json` - 개별 취약점 조회 (`GET /v1/vulns/{id}`) (hono 패키지)
- `package-vulnerabilities-api-response.json` - 패키지별 취약점 조회 (`POST /v1/query`) (lodash 패키지)
- `batch-query-api-response.json` - 여러 패키지 배치 조회 (`POST /v1/querybatch`)

## 각 파일의 용도

| 파일명 | 언제 사용? | 포함된 내용 |
|--------|-----------|-------------|
| `vulnerability-from-zip-download.json` | ZIP 다운로드 후 개별 파일 파싱할 때 | GHSA 파일 구조 |
| `single-vulnerability-api-response.json` | 특정 취약점 상세 정보가 필요할 때 | PoC 코드, 패치 링크, CVSS 점수 |
| `package-vulnerabilities-api-response.json` | 특정 패키지의 모든 취약점을 찾을 때 | 취약점 목록 배열 |
| `batch-query-api-response.json` | 여러 패키지를 한번에 조회할 때 | 여러 패키지 결과 배열 |

## CVE Collector에서 사용하는 방식

```python
# 1) 전체 GHSA 취약점 로드 (ZIP 캐시 기반)
all_ghsa = osv_client.get_all_npm_vulnerabilities(vuln_type="GHSA")
for ghsa_id, vulnerability_data in all_ghsa.items():
    # CVE ID 추출
    cve_id = next(
        (alias for alias in vulnerability_data.get("aliases", []) if alias.startswith("CVE")),
        None,
    )

# 2) 단일 취약점 상세 조회 (라이브 API)
vulnerability_data = osv_client.fetch_vulnerability_details("GHSA-2234-fmw7-43wr")
# → single-vulnerability-api-response.json 형태로 응답
```

## 주요 차이점

**ZIP vs API**
- ZIP 파일: 로컬에서 빠른 처리, 대량 데이터
- API 응답: 최신 데이터, 네트워크 필요

**개별 vs 배치**
- 개별 조회: 상세한 정보 (PoC, CVSS 등)
- 배치 조회: 여러 패키지 동시 처리

## 관련 API 엔드포인트

```bash
# 개별 취약점 상세 조회
curl https://api.osv.dev/v1/vulns/GHSA-2234-fmw7-43wr

# 패키지별 취약점 목록 조회
curl -X POST https://api.osv.dev/v1/query \
  -d '{"package": {"name": "lodash", "ecosystem": "npm"}}'

# 여러 패키지 배치 조회
curl -X POST https://api.osv.dev/v1/querybatch \
  -d '{"queries": [{"package": {"name": "express", "ecosystem": "npm"}}]}'
``` 