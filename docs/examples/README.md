# 예시 데이터 모음

CVE Collector 프로젝트에서 사용하는 다양한 API의 실제 응답 데이터 예시들을 모아둔 디렉토리입니다.

## 디렉토리 구조

### [`osv/`](osv/) - OSV API 관련 예시
OSV.dev에서 가져온 취약점 데이터 구조 예시들:
- ZIP 다운로드 파일 구조
- API 응답 형태 (개별/패키지/배치 조회)
- 실제 취약점 데이터 (hono, linux-cmdline, lodash 등)

### [`github/`](github/) - GitHub API 관련 예시
GitHub API에서 가져온 데이터 구조 예시들:
- Security Advisories 응답 (REST/GraphQL)
- Repository 정보
- Commit 및 패치 파일
- Rate limiting 헤더

## 사용 목적

### 1. 개발 참조
새로운 기능을 개발할 때 실제 API 응답 구조를 참조

### 2. 테스트 데이터
단위 테스트나 통합 테스트에서 실제 데이터 구조 사용

### 3. 문서화
API 응답 구조를 이해하고 문서화하기 위한 참조 자료

## CVE Collector에서의 활용

```python
# OSV API 예시 활용
with open("docs/examples/osv/single-vulnerability-api-response.json") as f:
    example_vuln = json.load(f)
    
# GitHub API 예시 활용 (REST/GraphQL)
with open("docs/examples/github/rest-single-advisory.json") as f:
    example_advisory = json.load(f)
```

## 파일 추가 가이드라인

새로운 예시 파일을 추가할 때는:

1. **적절한 디렉토리에 배치**: `osv/` 또는 `github/`
2. **직관적인 파일명 사용**: 용도를 명확히 알 수 있는 이름
3. **실제 데이터 사용**: 가공하지 않은 실제 API 응답 데이터
4. **README 업데이트**: 해당 디렉토리의 README에 파일 설명 추가

---

각 디렉토리의 자세한 내용은 해당 디렉토리 내 README.md 파일을 참조하세요. 