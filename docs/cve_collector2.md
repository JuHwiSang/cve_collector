CVE Collector 설계 문서 (현 네임스페이스: cve_collector)

## 목표와 원칙

- 목적: `src/cve_collector` 네임스페이스로 신규 구조를 구현한다.
- 아키텍처: app / core / infra / shared 레이어드 구조. app은 DI로 core의 포트를 구현한 infra 어댑터들을 주입한다.
- 사용 금지: 기존 `cve_collector` 모듈을 import 하지 않는다. 덕타이핑 임시방편 (`getattr`, `type: ignore`, `cast`)은 지양한다.
- 도메인 모델: 불변(immutable) 지향, 선택 필드(옵셔널) 중심으로 확장 가능하게 설계한다. 객체 직접 수정 대신 복제(copy) 기반으로 업데이트한다.
- 데이터 소스: OSV로부터 GHSA 목록(스켈레톤)을 확보하고, GitHub Security Advisory로 상세를 보강한다.
  - 참고 문서: [docs/osv_구조.md](./osv_구조.md), [docs/github_구조.md](./github_구조.md)

## Conventions

- 타입/덕타이핑 금지: `Any`, `cast`, `getattr`, `type: ignore` 사용 금지. `Protocol` 기반 포트로 구체 타입을 맞춘다.
- 도메인 모델: `dataclasses.dataclass(frozen=True)`로 불변. 변경은 `dataclasses.replace()`로 복제 업데이트.
- 검증/파싱 정책: infra 계층에서만 `pydantic` 모델(`OsvVulnerability`, `GitHubAdvisory`)로 검증한다. 정상 흐름에서 `isinstance`/키 존재 검사로 분기하지 않는다. 검증 실패는 그대로 예외로 전파한다.
- Fail-fast 예외 정책: 조용한 fallback/무시 금지. `try/except`는 문맥 정보 추가 후 즉시 재던지기(raise) 용도로만 사용한다. `continue`로 오류를 건너뛰지 않는다.
- 런타임 반사/동적 접근 금지: 정상 흐름 제어에 `getattr`/`hasattr`/딕셔너리 `get(..., default)`를 사용하지 않는다. 필요한 구조는 타입/모델로 정의한다.
- import 위치: 모든 import는 파일 최상단에 배치.
- URL 구성: 어댑터에서 문자열 결합 금지. `config/urls.py`의 `get_*_url` 함수 사용(예: `get_github_advisory_url`, `get_osv_vuln_url`).
- 캐시 규약: `DiskCacheAdapter`는 bytes 저장/반환이 기본이며, JSON 헬퍼(`get_json/set_json`)와 모델 헬퍼(`get_model/set_model`)를 제공한다. 위반 시 `TypeError`. 컨텍스트 매니저(`with`)로 사용.
- 키 포맷: `osv:{ID}`, `gh_advisory:{GHSA_ID}`, `gh_repo:{owner}/{name}`.
- 테스트 레이어드: core(unit), infra(integration), app(E2E). E2E는 실제 네트워크 호출을 수행하며 안정적인 공개 GHSA 식별자(예: `GHSA-2234-fmw7-43wr`)를 고정 사용한다. 캐시는 테스트 격리를 위해 `CVE_COLLECTOR_CACHE_DIR`로 분리한다.

추가 규약(라이브러리 API):
- 패키지 레벨 API 제공: `src/cve_collector/api.py`의 함수를 패키지 루트에서 재노출한다(`from cve_collector import list_vulnerabilities, detail, dump, clear_cache`).
- 각 API 함수는 호출 시 DI 컨테이너를 열고(use case 인스턴스 생성) 작업 종료 후 리소스를 정리한다.

추가 규약:
- GitHub Advisory의 `references`는 REST 버전에 따라 문자열 리스트 혹은 객체 리스트(`{ url: str }`)로 반환될 수 있다. 스키마는 두 형태를 모두 허용하며, 어댑터는 문자열이면 그대로 URL로, 객체면 `ref.url`로 정규화한다.
- CLI: 유즈케이스는 도메인 객체만 반환. 프리젠테이션은 app에서 포맷팅.

## 디렉토리 구조 (초안)

```
src/cve_collector/
  api.py                # 라이브러리 API (DI→유즈케이스 호출/반환)
  app/
    cli.py                 # 단일 진입점 (argparse/typer 등)
    container.py           # DI 조립(선택)

  core/
    domain/
      models.py            # Vulnerability, Repository, Commit 등 불변 도메인 모델
      enums.py             # Severity, ReferenceType 등 열거형
    ports/
      index_port.py         # 취약점 목록/조회 포트 (OSV 등)
      enrich_port.py       # 취약점 상세 보강 포트 (GitHub 등)
      dump_port.py         # 원본(raw) JSON 제공 포트 (dump)
      cache_port.py        # 캐시 포트 (get/set/clear/TTL)
      rate_limiter_port.py # 레이트리미터 포트 (선택)
      clock_port.py        # 시계/시간 포트 (테스트 용이성)
    usecases/
      list_vulnerabilities.py   # 전체 리스트 가져오기 (스켈레톤 혹은 경량 보강)
      detail_vulnerability.py   # 단건 상세 조회 + 보강 (식별자 문자열 기반)
      raw_dump.py               # 여러 RawProvider로부터 원본 JSON 배열 수집
      clear_cache.py            # 모든 캐시 비우기

  infra/
    osv_adapter.py         # OSV 기반 Adapter (Index + Enrichment 구현)
    github_enrichment.py   # GitHub GraphQL/REST 어댑터 (references→patch/PoC 추출)
    cache_diskcache.py     # diskcache 구현체
    http_client.py         # HTTP 클라이언트 + 타임아웃. JSON object 강제.
    rate_limiter.py        # 레이트 리미터(토큰버킷/단순 슬리프)

  shared/
    logging.py             # 로거 팩토리
    utils.py               # 공용 유틸 (URL 정규화, 키 생성 등)

  config/
    types.py               # 설정 타입 (AppConfig 등)
    loader.py              # 설정 로더 (env→AppConfig)
    urls.py                # 외부 API URL 빌더(get_*_url)
```

## OSV 스키마 구조 (infra/schemas.py)

OSV 데이터를 검증하기 위한 pydantic 모델들입니다. 전체 OSV 스키마를 표현하며, 버전 범위, 이벤트, 패키지 정보 등을 포함합니다.

```python
class OsvSeverity(BaseModel):
    """취약점 심각도 정보 (예: CVSS)"""
    type: str
    score: str | float

class OsvPackage(BaseModel):
    """영향을 받는 패키지 정보"""
    ecosystem: str
    name: str
    purl: Optional[str] = None

class OsvEvent(BaseModel):
    """버전 범위의 시작 또는 끝을 정의하는 이벤트"""
    introduced: Optional[str] = None
    fixed: Optional[str] = None
    last_affected: Optional[str] = None
    limit: Optional[str] = None

class OsvRange(BaseModel):
    """영향을 받는 버전 범위"""
    type: str
    repo: Optional[str] = None
    events: list[OsvEvent]

class OsvAffected(BaseModel):
    """취약점의 영향을 받는 패키지 및 버전 정보"""
    package: OsvPackage
    ranges: Optional[list[OsvRange]] = None
    versions: Optional[list[str]] = None
    ecosystem_specific: Optional[dict[str, Any]] = None
    database_specific: Optional[dict[str, Any]] = None

class OsvReference(BaseModel):
    """관련 외부 참조 링크"""
    type: str | None = None
    url: str

class OsvVulnerability(BaseModel):
    """OSV 스키마의 최상위 모델"""
    schema_version: Optional[str] = Field(None, alias='schema_version')
    id: str
    modified: Optional[str] = None  # 테스트 호환성을 위해 optional
    published: Optional[str] = None
    withdrawn: Optional[str] = None
    aliases: Optional[list[str]] = None
    related: Optional[list[str]] = None
    summary: Optional[str] = None
    details: Optional[str] = None
    severity: Optional[list[OsvSeverity]] = None
    affected: list[OsvAffected] | None = None
    references: Optional[list[OsvReference]] = None
    database_specific: Optional[dict[str, Any]] = None
```

주요 특징:
- `modified` 필드는 OSV 표준에서는 필수이나, 테스트 호환성을 위해 optional로 설정
- `affected` 리스트를 통해 영향받는 패키지와 버전 범위를 표현
- `ranges`와 `events`를 통해 복잡한 버전 범위 표현 가능 (introduced/fixed/last_affected)
- `ecosystem` 필터링은 `affected[].package.ecosystem` 기반으로 수행

## 도메인 모델 (불변, 확장 가능)

표준 라이브러리 중심으로 시작하고, 필요시 pydantic으로 확장한다. 기본은 dataclass(frozen=True)로 불변을 보장하고, 업데이트는 `dataclasses.replace()`를 사용한다.

```python
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum
from typing import Optional, Sequence


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class ReferenceType(Enum):
    ADVISORY = "ADVISORY"
    WEB = "WEB"
    FIX = "FIX"
    PACKAGE = "PACKAGE"
    OTHER = "OTHER"


@dataclass(frozen=True)
class Repository:
    platform: Optional[str] = None  # e.g., "github"
    owner: Optional[str] = None
    name: Optional[str] = None
    star_count: Optional[int] = None
    size_bytes: Optional[int] = None
    ecosystem: Optional[str] = None  # e.g., "npm", "pypi", "go"

    @property
    def slug(self) -> Optional[str]:
        if self.owner and self.name:
            return f"{self.owner}/{self.name}"
        return None

    @property
    def url(self) -> Optional[str]:
        if self.platform == "github" and self.slug:
            return f"https://github.com/{self.slug}"
        return None

    def commit_url(self, commit_hash: str) -> Optional[str]:
        base = self.url
        if base and commit_hash:
            return f"{base}/commit/{commit_hash}"
        return None

    @staticmethod
    def from_github(owner: str, name: str, *, stars: Optional[int] = None, size_bytes: Optional[int] = None, ecosystem: Optional[str] = None) -> "Repository":
        return Repository(platform="github", owner=owner, name=name, star_count=stars, size_bytes=size_bytes, ecosystem=ecosystem)


@dataclass(frozen=True)
class Commit:
    repo: Repository
    hash: str

    @property
    def short_hash(self) -> str:
        return self.hash[:12] if self.hash else ""

    @property
    def url(self) -> Optional[str]:
        return self.repo.commit_url(self.hash)


@dataclass(frozen=True)
class Vulnerability:
    # 식별자
    ghsa_id: str
    cve_id: Optional[str] = None

    # 요약/본문
    summary: Optional[str] = None
    description: Optional[str] = None

    # 메타
    severity: Severity | None = None
    published_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None

    # 저장소/커밋/PoC
    repositories: tuple[Repository, ...] = field(default_factory=tuple)
    commits: tuple[Commit, ...] = field(default_factory=tuple)
    poc_urls: tuple[str, ...] = field(default_factory=tuple)

    # 자유 확장 슬롯 (키-값 메타)
    extra: dict[str, object] = field(default_factory=dict, compare=False)

    def with_updates(self, **kwargs) -> "Vulnerability":
        return replace(self, **kwargs)
```

참고: pydantic을 사용할 경우 `model_config = dict(frozen=True)` + `model_copy(update=...)`로 동일한 불변/복제 패턴을 유지할 수 있다.

## 포트(Protocols)

핵심 의도는 “취약점 목록 가져오기”와 “취약점 상세정보 보강”의 두 축이다. 추가로 캐시/레이트리미터를 포트로 분리한다.

```python
from __future__ import annotations

from typing import Iterable, Protocol, Sequence

from cve_collector.core.domain.models import Vulnerability


class VulnerabilityIndexPort(Protocol):
    def list(self, *, ecosystem: str | None = None, limit: int | None = None) -> Sequence[Vulnerability]:
        """GHSA 중심의 스켈레톤 목록을 반환. (요약/aliases 등 최소 정보)

        ecosystem이 None이면 모든 ecosystem의 취약점을 반환한다.
        ecosystem이 지정되면 해당 ecosystem만 필터링하여 반환한다.
        구현 예: OSV GHSA 파일/검색 결과를 파싱해 Vulnerability 생성
        """

    def get(self, selector: str) -> Vulnerability | None:
        """식별자 문자열로 단건 조회. 예: "GHSA-...", "CVE-...".
        구현체는 접두사 등 규칙으로 해석한다. 없으면 None.
        """


class VulnerabilityEnrichmentPort(Protocol):
    def enrich(self, v: Vulnerability) -> Vulnerability:
        """입력 Vulnerability를 기반으로 새 인스턴스를 반환.
        예: GH Advisory/커밋/레포 정보로 repositories/commits/poc_urls 보강.
        """

    def enrich_many(self, items: Iterable[Vulnerability]) -> Iterable[Vulnerability]:
        for v in items:
            yield self.enrich(v)


class DumpProviderPort(Protocol):
    def dump(self, selector: str) -> dict | None:
        """식별자(GHSA-..., CVE-...)에 대한 원본 JSON을 반환. 없으면 None."""
        ...


class CachePort(Protocol):
    def get(self, key: str) -> bytes | None: ...
    def set(self, key: str, value: bytes, ttl_seconds: int | None = None) -> None: ...
    def clear(self) -> None: ...


class RateLimiterPort(Protocol):
    def acquire(self) -> None: ...  # 간단한 동기 API (필요시 컨텍스트/async 버전 추가)
```

컴포지트 보강기(Composite Enricher)를 통해 여러 보강기를 순차 적용할 수 있다.

```python
from collections.abc import Iterable
from typing import Sequence


class CompositeEnricher:
    def __init__(self, enrichers: Sequence[VulnerabilityEnrichmentPort]) -> None:
        self._enrichers = tuple(enrichers)

    def enrich(self, v: Vulnerability) -> Vulnerability:
        enriched = v
        for enricher in self._enrichers:
            enriched = enricher.enrich(enriched)
        return enriched

    def enrich_many(self, items: Iterable[Vulnerability]) -> Iterable[Vulnerability]:
        for v in items:
            yield self.enrich(v)
```

## 유즈케이스

요구사항에 따라 세 가지 유즈케이스를 정의한다. 반환 타입은 도메인 모델 또는 프리젠테이션 친화 형태(목록/단건)이며, app 계층에서 보기 좋게 출력 포맷팅을 수행한다.

1) 전체 리스트 출력용 (list 객체 반환)

```python
from typing import Sequence


class ListVulnerabilitiesUseCase:
    def __init__(self, index: VulnerabilityIndexPort, enricher: VulnerabilityEnrichmentPort | None = None) -> None:
        self._index = index
        self._enricher = enricher

    def execute(self, *, ecosystem: str | None = None, limit: int | None = None, detailed: bool = False) -> Sequence[Vulnerability]:
        items = self._index.list(ecosystem=ecosystem, limit=limit)
        if not detailed or not self._enricher:
            return items
        return list(self._enricher.enrich_many(items))
```

2) 단건 상세 출력용 (식별자 문자열 기반, 필요시 보강 적용)

```python
class DetailVulnerabilityUseCase:
    def __init__(self, index: VulnerabilityIndexPort, enricher: VulnerabilityEnrichmentPort | None = None) -> None:
        self._index = index
        self._enricher = enricher

    def execute(self, selector: str) -> Vulnerability | None:
        v = self._index.get(selector)
        if v is None:
            return None
        if self._enricher is None:
            return v
        return self._enricher.enrich(v)
```

3) Raw 덤프 (원본 JSON 모음)

```python
class RawDumpUseCase:
    def __init__(self, providers: Sequence[DumpProviderPort]) -> None:
        self._providers = tuple(providers)

    def execute(self, selector: str) -> list[dict]:
        results: list[dict] = []
        for p in self._providers:
            payload = p.dump(selector)
            if payload is not None:
                results.append(payload)
        return results
```

4) 모든 캐시 삭제

```python
class ClearCacheUseCase:
    def __init__(self, cache: CachePort) -> None:
        self._cache = cache

    def execute(self) -> None:
        self._cache.clear()
```

## Infra 어댑터 개요

- OSV Adapter (`infra/osv_adapter.py`)
  - 역할: OSV Index + Enrichment + Dump (세 포트 구현)
  - 입력: OSV ecosystem ZIP(`.../{ecosystem}/all.zip`) 다운로드 → GHSA 파일 필터 → 각 항목을 `osv:{id}`로 개별 저장
  - 캐시 키: 각 항목 `osv:{ID}` (리스트 키 없음)
  - `list(ecosystem, limit)`: 캐시의 `osv:` 프리픽스 키들을 스캔(`iter_keys`) → 각 항목을 모델로 로드(`get_model(OsvVulnerability)`) → `Vulnerability` 변환 후 반환.
    - `ecosystem=None`: 모든 ecosystem의 취약점 반환 (필터링 없음)
    - `ecosystem` 지정: `affected[].package.ecosystem`이 일치하는 항목만 필터링하여 반환
    - 캐시가 비어 있을 때:
      - `ecosystem=None`이면 명확한 에러 메시지 출력 (ingest 필요)
      - `ecosystem` 지정 시 자동으로 ZIP ingest 후 재스캔
  - `get(selector)`: 문자열 식별자(`GHSA-...`, `CVE-...`)에 대해 `dump(selector)`로 원본을 확보/캐싱한 뒤 모델 검증 → 도메인 변환하여 반환.
  - `dump(selector)`: OSV API에서 식별자 기반으로 JSON을 가져와 `osv:{id}`로 캐시 후 그대로 반환.
  - `enrich(v)`: OSV 정보로 다음 필드를 보강한다
    - `cve_id`: `aliases`에서 CVE 추출
    - `ecosystem`: `affected[0].package.ecosystem`에서 추출 (npm, pypi, go 등)
    - `severity`: OSV `severity`가 문자열 또는 목록일 수 있으므로, 문자열은 `Severity.from_str`로, 목록은 최신 타입의 `score`를 `Severity.from_str`로 매핑
    - `summary`/`description`/`details`: OSV `summary`/`details`로 보완하고 `details`도 보존
    - `published_at`/`modified_at`: ISO 타임스탬프 파싱
    - `repositories`/`commits`/`poc_urls`: OSV `references`의 타입/URL을 활용해 추출하며, 추출된 Repository에 ecosystem 정보를 포함 (예: FIX/WEB/OTHER → 커밋 우선, PACKAGE/WEB → 저장소, WEB/OTHER → PoC 후보 URL)
  - 출력: `Vulnerability(ghsa_id=..., cve_id=..., summary, details, severity, ...)`
  - 참고: [docs/osv_구조.md](./osv_구조.md)

- GitHub Enrichment (`infra/github_enrichment.py`)
  - 역할: GitHub Repo 메타데이터(주로 star 수, 레포 크기) 보강
    - 입력 `Vulnerability.repositories`에 존재하는 GitHub repo에 대해 `stargazers_count`와 `size`를 조회하여 보강
    - GitHub API의 `size` 필드는 KB 단위로 반환되므로 1024를 곱해 bytes로 변환하여 `size_bytes`에 저장
  - 캐싱: CachePort로 응답 캐시 (기본 TTL 30일). 키 포맷 예: `gh_repo:{owner}/{name}`
  - URL: `config/urls.py`의 `get_github_repo_url(owner, name)` 사용
  - RateLimit: RateLimiterPort 사용 권장

- DiskCache (`infra/cache_diskcache.py`)
  - 역할: `get/set/clear_all` + `iter_keys(prefix)` 구현. JSON/모델 헬퍼는 `CachePort` 기본 구현 사용. 디렉토리: `platformdirs` 사용자 캐시 디렉토리 하위 네임스페이스 분리
  - 직렬화: 모델 검증/매핑은 외부 레이어에서 수행하며, 캐시는 JSON 직렬화만 담당한다.
  - 금지 규칙: import 실패 시 대체 구현(fallback) 금지. 필요 모듈 미설치면 즉시 에러.
  - 리소스 관리: `clear()`로 비우기, `close()`로 종료. 컨텍스트 매니저(with) 지원.

- HTTP Client (`infra/http_client.py`)
  - 역할: 세션 재사용, 타임아웃. 응답코드 비정상이면 즉시 예외. JSON은 object만 허용.
  - 인증 헤더: `app/container.py`에서 `GITHUB_TOKEN`이 설정된 경우 Authorization/Accept/X-GitHub-Api-Version 헤더를 주입한다.

## CLI (app/cli.py)

- Typer 기반 단일 엔트리포인트. 출력은 보기 좋게(테이블/하이라이트) 구성하되, 유즈케이스는 도메인 객체만 반환.
- 명령:
- `cve_collector list` # ecosystem 미지정 시 모든 ecosystem 표시 (캐시 필요)
- `cve_collector list --ecosystem npm --limit 50`
- `cve_collector list -d` (또는 `--detail`) # 상세 모드: 심각도, 에코시스템, 레포, 스타, 크기 포함
- `cve_collector detail GHSA-xxxx-xxxx-xxxx`
- `cve_collector detail CVE-YYYY-NNNNN`
- `cve_collector dump GHSA-xxxx-xxxx-xxxx`  # 구성된 RawProvider들의 원본 JSON 배열 출력
- `cve_collector clear`
- 설치 및 실행:
  - `pip install -e .` 후 `cve_collector ...` 스크립트 호출 (pyproject `[project.scripts]`).
- 에러 처리: 비정상 상황은 `typer.Exit(code=1)`로 명시 종료. 조용한 fallback 금지.
- 덕타이핑 금지: `Any`, `cast`, `getattr`, `type: ignore` 금지. 출력 함수 시그니처는 구체 타입(`Sequence[Vulnerability]`, `Vulnerability`).

## 라이브러리 API (api.py)

- 목적: 라이브러리로 사용할 때 간단한 함수 호출로 유즈케이스를 실행한다.
- DI: 함수마다 내부에서 컨테이너를 생성/초기화하고, 종료 시 리소스를 해제한다.
- 내보내기: 패키지 루트에서 재노출되어 바로 임포트 가능하다.

사용 예:

```python
from cve_collector import list_vulnerabilities, detail, dump, clear_cache

# 리스트 (필요 시 상세 보강)
items = list_vulnerabilities(ecosystem="npm", limit=50, detailed=True)

# 단건 상세 (식별자: GHSA-... 또는 CVE-...)
v = detail("GHSA-2234-fmw7-43wr")

# 원본 JSON 덤프 (여러 Provider의 페이로드 배열)
payloads = dump("GHSA-2234-fmw7-43wr")

# 캐시 비우기
clear_cache()
```

## DI 조립 (dependency-injector)

```python
from dependency_injector import containers, providers
from cve_collector.config.loader import load_config
from cve_collector.config.types import AppConfig
from cve_collector.core.services.composite_enricher import CompositeEnricher
from cve_collector.core.usecases import list_vulnerabilities, detail_vulnerability, clear_cache
from cve_collector.infra.cache_diskcache import DiskCacheAdapter
from cve_collector.infra.github_enrichment import GitHubRepoEnricher
from cve_collector.infra.osv_adapter import OSVAdapter
from cve_collector.infra.rate_limiter import SimpleRateLimiter


def cache_resource(app_cfg: AppConfig):
  with DiskCacheAdapter(namespace="github", default_ttl_seconds=30*24*3600, base_dir=app_cfg.cache_dir) as cache:
    yield cache


class Container(containers.DeclarativeContainer):
  config = providers.Configuration()

  app_config = providers.Callable(load_config)
  cache = providers.Resource(cache_resource, app_config)

  rate_limiter = providers.Factory(SimpleRateLimiter, rps=1.5)
  index = providers.Factory(OSVAdapter, cache=cache)

  enrichers = providers.List(
    providers.Factory(GitHubRepoEnricher, cache=cache),
  )
  raw_providers = providers.List(
    providers.Factory(GitHubRepoEnricher, cache=cache),
  )
  composite_enricher = providers.Factory(CompositeEnricher, enrichers=enrichers)

  list_uc = providers.Factory(list_vulnerabilities.ListVulnerabilitiesUseCase, index=index, enricher=composite_enricher)
  detail_uc = providers.Factory(detail_vulnerability.DetailVulnerabilityUseCase, index=index, enricher=composite_enricher)
  raw_uc = providers.Factory(raw_dump.RawDumpUseCase, providers=raw_providers)
  clear_cache_uc = providers.Factory(clear_cache.ClearCacheUseCase, cache=cache)
```

메모:
- Enricher는 providers.List로 여러 구현을 주입할 수 있고, 필요 시 `DetailVulnerabilityUseCase`에 리스트 자체를 넣는 대신 `CompositeEnricher`를 통해 순차 적용한다.

## 캐시/성능/에러 처리 지침

- 캐시 키: 데이터 소스/엔드포인트/파라미터가 드러나게 구성한다. 예) `osv:{ID}`, `gh_advisory:{GHSA_ID}`, `gh_repo:{owner}/{name}`.
- TTL: GitHub 30일, OSV 7일(권장). CLI 옵션으로 오버라이드 가능.
- 동시성: 초기엔 동기 구현 후, 대용량 처리 시 `ThreadPoolExecutor`로 보강(Enricher의 `enrich_many`).
- 에러 처리: 
  - 404/Null: 존재하지 않는 GHSA는 None 처리, CLI는 친절한 메시지 출력
  - 403: Rate limit 초과 시 대기 또는 즉시 실패 후 재시도 힌트 제공
  - 네트워크: 타임아웃/재시도(지수 백오프) 기본 적용

## 출력 규칙 (app 레벨)

- 리스트: 기본 GHSA, CVE만 출력. `--detail` 사용 시 심각도, 에코시스템, 주요 레포(`owner/name★stars size`) 컬럼을 추가로 출력한다.
  - 컬럼 순서: GHSA, CVE, Severity, Eco, Repository, Stars, Size
  - 에코시스템은 8자 폭으로 표시 (npm, pypi, go 등)
  - 크기는 적절한 단위(B, KB, MB, GB)로 자동 변환하여 표시
- 단건: 요약, 심각도, 발행/수정일, 레포 목록([ecosystem] slug, stars, size), 커밋 목록(짧은 해시+URL), PoC 링크
- 컬러링/폭 자르기 등 프리젠테이션은 app에서만 처리하고, core/infra는 관여하지 않는다.

## 마이그레이션 메모

- 기존 `src/cve_collector`는 import하지 않는다. 로직 재사용이 필요하면 개념/파싱 규칙을 문서만 참고한다.
- 단계적 전환 메모는 제거. 본 문서는 `cve` 바이너리를 기준으로 한다.

## 구현 로드맵 (제안)

1. shared/core 뼈대 생성: `domain.models`, `ports`, `usecases`
2. infra 최소 구현: `OSVIndexAdapter`(로컬 파일/한정된 API) → `GitHubRepoEnricher`
3. cache/http/rate_limiter 어댑터 도입 및 DI 연결
4. app/cli 구현: `list`, `show`, `cache clear` 명령
5. 테스트 정비(pyproject의 optional deps 활용), 출력 포맷팅 개선, 동시성 최적화, 캐시 전략 튜닝

---

이 문서는 v2 구현의 기준서이며, 상세 스펙 변경은 본 문서에 누적 기록한다.


