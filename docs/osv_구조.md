# OSV (Open Source Vulnerability) 구조

OSV.dev의 npm 생태계 취약점 데이터 구조에 대한 분석입니다.

## 1. OSV.dev 개요

- **공식 사이트**: [osv.dev](https://osv.dev/)
- **개발**: Google (OpenSSF 산하)
- **스키마**: [OSV Schema v1.6.0](https://ossf.github.io/osv-schema/)

### npm 생태계 현황 (2025년 기준)
```
총 취약점 수: 26,021개
├── MAL-*: ~22,000개 (Malicious packages) ← 대부분이 악성 패키지
├── GHSA-*: ~3,948개 (GitHub Security Advisory) ← 우리가 사용할 부분  
└── GSD-*: ~1개 (Global Security Database)
```

## 2. 데이터 수집 방법

### 전체 데이터베이스 다운로드

```bash
# 전체 npm 취약점 ZIP 다운로드 (~50MB)
curl -O https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
unzip npm/all.zip -d osv_npm/
```

**압축 해제 후 구조:**
```
osv_npm/
├── GHSA-2c29-wc65-4cx9.json    # GitHub Security Advisory (약 3,948개)
├── GHSA-xxxx-yyyy-zzzz.json    # 실제 취약점 정보가 있는 파일들
├── MAL-2024-1234.json          # 악성 패키지 (약 22,000개, 사용 안함)
└── GSD-2024-5678.json          # 글로벌 보안 DB (1개)
```

### API를 통한 조회

```bash
# 특정 취약점 상세 정보
GET https://api.osv.dev/v1/vulns/GHSA-2c29-wc65-4cx9
```

## 3. GHSA 파일 구조

**예시**: [`examples/osv/vulnerability-from-zip-download.json`](examples/osv/vulnerability-from-zip-download.json)

### 주요 필드

| 필드 | 타입 | 설명 | 예시 |
|------|------|------|------|
| `id` | string | GHSA 식별자 | `"GHSA-2c29-wc65-4cx9"` |
| `aliases` | array | CVE ID 등 | `["CVE-2020-7704"]` |
| `summary` | string | 취약점 요약 | `"Prototype Pollution vulnerability"` |
| `details` | string | 상세 설명 | `"The package is vulnerable to..."` |
| `modified` | string | 최종 수정 시간 | `"2025-01-14T08:57:21.582603Z"` |
| `published` | string | 최초 공개 시간 | `"2022-05-24T17:26:04Z"` |

### affected 필드 (패키지 정보)

```json
{
  "affected": [
    {
      "package": {
        "name": "linux-cmdline",
        "ecosystem": "npm"
      },
      "ranges": [
        {
          "type": "SEMVER",
          "events": [
            {"introduced": "0"},
            {"fixed": "1.0.1"}
          ]
        }
      ]
    }
  ]
}
```

### references 필드 (관련 링크)

```json
{
  "references": [
    {
      "type": "ADVISORY",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-7704"
    },
    {
      "type": "WEB",
      "url": "https://github.com/owner/repo/commit/abc123"
    },
    {
      "type": "PACKAGE", 
      "url": "https://github.com/owner/repo"
    }
  ]
}
```

### reference 타입별 용도

| type | 설명 | 패치 추출 여부 |
|------|------|---------------|
| `ADVISORY` | 공식 보안 권고 | ❌ |
| `WEB` | 일반 웹 링크 (종종 커밋) | ✅ |
| `FIX` | 패치 커밋 | ✅ |
| `PACKAGE` | 패키지 홈페이지 | ❌ |

## 4. 중요한 특징

### CVE ID 매핑
- 파일명은 `GHSA-xxxx-xxxx-xxxx` 형태
- 실제 CVE ID는 `aliases` 필드에 있음
- 모든 GHSA가 CVE를 가지는 것은 아님 (~80%)

### 패치/PoC 링크 추출
- `references` 필드에서 GitHub 커밋 링크 찾기 → `/commit/` 포함이면 패치로 간주
- PoC는 URL에 `poc|exploit|demo|payload|reproduce` 키워드가 포함된 경우로 탐지

### 패키지 정보
- `affected[0].package.name`에서 패키지명 추출
- 하나의 GHSA가 여러 패키지에 영향을 줄 수 있음
- 첫 번째 패키지를 대표 패키지로 사용

### 데이터 품질
- **GHSA 파일**: 실제 보안 취약점 정보 (약 3,948개)
- **MAL 파일**: 악성 패키지 정보 (약 22,000개) - CVE Collector에서 사용 안함
- **GSD 파일**: 글로벌 보안 DB (1개) - 거의 사용되지 않음

---

자세한 예시는 [`examples/osv/`](examples/osv/) 디렉토리를 참조하세요.
