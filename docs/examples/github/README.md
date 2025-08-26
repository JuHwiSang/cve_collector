# GitHub API 예시 데이터

GitHub API에서 가져온 실제 응답 데이터 예시들입니다.

## GitHub API 사용 패턴

CVE Collector에서 GitHub API를 사용하는 주요 패턴들:

```python
# 1. Security Advisories 배치 조회
advisories = github_client.fetch_security_advisories_batch(["GHSA-xxxx-..."], batch_size=50)

# 2. 리포지토리 정보
repo_info = github_client.get_repository_info("owner", "repo")

# 3. 패치 파일 다운로드
github_client.download_patch_file("owner", "repo", "abcdef123", Path("./abcdef123.patch"))
```

## 관련 GitHub API 엔드포인트

```bash
# Security Advisory 조회
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/advisories/GHSA-xxxx-xxxx-xxxx

# 리포지토리 정보 조회  
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/repos/owner/repo

# 커밋 정보 조회
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/repos/owner/repo/commits/sha
```

---

*📝 이 디렉토리는 현재 비어있으며, GitHub API 관련 기능 개발 시 예시 파일들이 추가될 예정입니다.*

## GitHub Security Advisory API 예시

이 디렉토리는 GitHub Security Advisory API의 요청과 응답 예시를 포함합니다.

## 파일 목록

### REST API 예시
- `rest-single-advisory.json` - 단일 Advisory 조회 응답 예시

Note: The REST example is simplified/normalized for illustration. The real GitHub response includes many more fields and often uses camelCase keys. Refer to the official docs for the exact schema.

### GraphQL API 예시  
- `graphql-batch-request.json` - 배치 조회 요청 예시
- `graphql-batch-response.json` - 배치 조회 응답 예시

## 사용법

### REST API
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     https://api.github.com/advisories/GHSA-xxxx-xxxx-xxxx
```

### GraphQL API
```bash
curl -X POST \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d @graphql-batch-request.json \
     https://api.github.com/graphql
```

## 주요 특징

### References 패턴
- **패치 링크**: `/commit/` 포함된 GitHub URL
- **PoC 저장소**: `poc`, `exploit`, `demo` 등 키워드 포함
- **공식 문서**: NVD, MITRE 등 공식 사이트

### GraphQL 배치 처리
- alias 사용하여 여러 Advisory 동시 조회
- 일부 실패시 null 반환 (전체 요청은 성공)
- Rate limit 절약 효과

## 관련 문서

- [GitHub 구조 분석](../../github_구조.md)
- [GitHub GraphQL API 문서](https://docs.github.com/en/graphql) 