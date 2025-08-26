# GitHub Security Advisory API 구조 분석

## 개요

GitHub Security Advisory API는 GitHub에서 관리하는 보안 권고사항 데이터베이스에 접근할 수 있는 API입니다. CVE 정보, 패치 링크, 영향받는 패키지 등의 정보를 제공합니다.

## API 방식

### 1. REST API
- **엔드포인트**: `https://api.github.com/advisories/{ghsa_id}`
- **방식**: 개별 Advisory 조회
- **장점**: 단순한 구조, 직관적 사용
- **단점**: 대량 조회시 많은 API 호출 필요

### 2. GraphQL API
- **엔드포인트**: `https://api.github.com/graphql`
- **방식**: 배치 조회 가능 (alias 활용)
- **장점**: 한 번에 여러 Advisory 조회, Rate limit 절약
- **단점**: 복잡한 쿼리 생성 필요

## 데이터 구조

### Security Advisory 객체

| 필드 | 타입 | 설명 | 예시 |
|------|------|------|------|
| `ghsaId` | String | GitHub Security Advisory ID | `"GHSA-xxxx-xxxx-xxxx"` |
| `summary` | String | 취약점 요약 | `"SQL injection vulnerability"` |
| `description` | String | 상세 설명 | `"A SQL injection vulnerability..."` |
| `publishedAt` | DateTime | 발행 일시 | `"2024-01-15T10:30:00Z"` |
| `updatedAt` | DateTime | 수정 일시 | `"2024-01-16T14:20:00Z"` |
| `severity` | Enum | 심각도 | `"HIGH"`, `"CRITICAL"`, `"MEDIUM"`, `"LOW"` |
| `references` | Array | 참조 링크 배열 | 패치 커밋, 문서 등 |
| `identifiers` | Array | 식별자 배열 | CVE, GHSA 등 |

### References 구조

```json
{
  "references": [
    {
      "url": "https://github.com/owner/repo/commit/abc123"
    },
    {
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
    }
  ]
}
```

**주요 패턴:**
- GitHub 커밋 링크: `/commit/` 포함 → 패치 정보
- PoC 저장소: `poc`, `exploit`, `demo` 등 키워드 포함
- 공식 문서: NVD, MITRE 등 공식 사이트

### Identifiers 구조

```json
{
  "identifiers": [
    {
      "type": "GHSA",
      "value": "GHSA-xxxx-xxxx-xxxx"
    },
    {
      "type": "CVE", 
      "value": "CVE-2024-1234"
    }
  ]
}
```

## API 사용 패턴

### 1. 개별 조회 (REST)

```http
GET /advisories/GHSA-xxxx-xxxx-xxxx
Authorization: Bearer TOKEN
```

**캐시 전략:**
- 백엔드: diskcache (디렉토리: `helpers.get_cache_dir()/github`)
- 키 형식: `advisory:{ghsa_id}`
- TTL: 기본 30일 (GitHubClient.DEFAULT_CACHE_TTL)

### 2. 배치 조회 (GraphQL)

```graphql
query BatchAdvisories {
  adv1: securityAdvisory(ghsaId: "GHSA-1111-2222-3333") {
    ghsaId
    references { url }
  }
  adv2: securityAdvisory(ghsaId: "GHSA-4444-5555-6666") {
    ghsaId  
    references { url }
  }
}
```

**배치 전략:**
- 크기: 20-50개 권장
- 동적 alias 생성: `adv1`, `adv2`, ...
- 에러 처리: 일부 실패시 null 반환

## Rate Limiting

### REST API
- **제한**: 시간당 5,000 요청 (인증된 사용자)
- **권장**: 초당 1.5 요청으로 보수적 설정

### GraphQL API  
- **제한**: 복잡도 기반 (쿼리당 최대 5,000 포인트)
- **배치**: 50개 배치시 약 500-1000 포인트 소모
- **권장**: 초당 2-3 배치 정도

## 프로젝트에서의 활용

### 데이터 플로우

1. **OSV 데이터**: GHSA ID 목록 수집
2. **GitHub API**: GHSA ID → Advisory 상세 정보
3. **패치 추출**: `references` 필드에서 커밋 링크 추출
4. **PoC 추출**: `references` 필드에서 PoC 저장소 링크 추출

### 캐시 구조

- 디렉토리: `{cache_dir}/github` (platformdirs 기반 사용자 캐시 경로)
- 내부 구조는 diskcache 구현에 따르며, 고정 파일명이 아닌 key/value 저장소입니다.
  - key 예시: `advisory:GHSA-1111-2222-3333`
  - value: Pydantic 모델(`GHAdvisoryNode`) 직렬화 결과

### 성능 비교

| 방식 | API 호출 수 | 예상 시간 | Rate Limit 소모 |
|------|-------------|-----------|-----------------|
| REST 개별 | 3,948회 | ~44분 | 79% |
| GraphQL 배치 | ~80회 | ~1분 | 8% |

## 에러 처리

### 공통 에러
- `404`: Advisory 존재하지 않음
- `403`: Rate limit 초과
- `401`: 인증 실패

### GraphQL 특이사항
- 일부 Advisory가 null이어도 전체 응답은 200
- `errors` 필드에서 개별 에러 확인 필요

## 실제 사용 예시

프로젝트에서는 다음과 같이 활용:

1. **CVECollector**: OSV 데이터에서 GHSA 취약점을 로드하고 `CVE` 객체로 변환
2. **GitHubClient**: GHSA ID로 Advisory 배치 조회(캐시 우선) 후 `references` 적용
3. **패치 정보**: `references`에서 `/commit/` 링크 추출하여 `patches`/`commits`/`repo` 채움
4. **PoC 정보**: `references` URL에서 PoC 패턴(`poc|exploit|demo|payload|reproduce`) 매칭

## 관련 문서

- [GitHub GraphQL API 문서](https://docs.github.com/en/graphql)
- [Security Advisory Schema](https://docs.github.com/en/graphql/reference/objects#securityadvisory)
- [요청-응답 예시](./examples/github/) 