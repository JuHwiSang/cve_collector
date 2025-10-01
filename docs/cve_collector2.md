CVE Collector 설계 문서 (현 네임스페이스: cve_collector)

## 목표와 원칙

- 목적: `src/cve_collector` 네임스페이스로 신규 구조를 구현한다.
- 아키텍처: app / core / infra / shared 레이어드 구조. app은 DI로 core의 포트를 구현한 infra 어댑터들을 주입한다.
- 사용 금지: 기존 `cve_collector` 모듈을 import 하지 않는다. 덕타이핑 임시방편 (`getattr`, `type: ignore`, `cast`)은 지양한다.
- 도메인 모델: 불변(immutable) 지향, 선택 필드(옵셔널) 중심으로 확장 가능하게 설계한다. 객체 직접 수정 대신 복제(copy) 기반으로 업데이트한다.
- 데이터 소스: OSV로부터 GHSA 목록(스켈레톤)을 확보하고, GitHub Security Advisory로 상세를 보강한다.
  - 참고 문서: [docs/osv_구조.md](./osv_구조.md), [docs/github_구조.md](./github_구조.md)

## 디렉토리 구조 (초안)

```
src/cve_collector/
  app/
    cli.py                 # 단일 진입점 (argparse/typer 등)
    container.py           # DI 조립(선택)

  core/
    domain/
      models.py            # Vulnerability, Repository, Commit 등 불변 도메인 모델
      enums.py             # Severity, ReferenceType 등 열거형
    ports/
      index_port.py        # 취약점 목록/조회 포트 (OSV 등)
      enrich_port.py       # 취약점 상세 보강 포트 (GitHub 등)
      cache_port.py        # 캐시 포트 (get/set/clear/TTL)
      rate_limiter_port.py # 레이트리미터 포트 (선택)
      clock_port.py        # 시계/시간 포트 (테스트 용이성)
    usecases/
      list_vulnerabilities.py   # 전체 리스트 가져오기 (스켈레톤 혹은 경량 보강)
      show_vulnerability.py     # GHSA 단건 조회 + 보강
      clear_cache.py            # 모든 캐시 비우기

  infra/
    osv_index.py           # OSV 기반 Index 어댑터 (GHSA 스켈레톤 리스트)
    github_enrichment.py   # GitHub GraphQL/REST 어댑터 (references→patch/PoC 추출)
    cache_diskcache.py     # diskcache 구현체
    http_client.py         # HTTP 클라이언트 + 재시도/백오프
    rate_limiter.py        # 레이트 리미터(토큰버킷/단순 슬리프)
    settings.py            # 환경변수/설정 로더 (토큰/TTL/경로)

  shared/
    logging.py             # 로거 팩토리
    utils.py               # 공용 유틸 (URL 정규화, 키 생성 등)

  config/
    types.py               # 설정 타입 (AppConfig 등)
    loader.py              # 설정 로더 (env→AppConfig)
```

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
    def from_github(owner: str, name: str, *, stars: Optional[int] = None) -> "Repository":
        return Repository(platform="github", owner=owner, name=name, star_count=stars)


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
    def list(self, *, ecosystem: str, limit: int | None = None) -> Sequence[Vulnerability]:
        """GHSA 중심의 스켈레톤 목록을 반환. (요약/aliases 등 최소 정보)
        구현 예: OSV GHSA 파일/검색 결과를 파싱해 Vulnerability 생성
        """

    def get_by_ghsa(self, ghsa_id: str) -> Vulnerability | None:
        """단건 스켈레톤 조회. 없으면 None."""


class VulnerabilityEnrichmentPort(Protocol):
    def enrich(self, v: Vulnerability) -> Vulnerability:
        """입력 Vulnerability를 기반으로 새 인스턴스를 반환.
        예: GH Advisory/커밋/레포 정보로 repositories/commits/poc_urls 보강.
        """

    def enrich_many(self, items: Iterable[Vulnerability]) -> Iterable[Vulnerability]:
        for v in items:
            yield self.enrich(v)


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
    def __init__(self, index: VulnerabilityIndexPort) -> None:
        self._index = index

    def execute(self, *, ecosystem: str, limit: int | None = None) -> Sequence[Vulnerability]:
        return self._index.list(ecosystem=ecosystem, limit=limit)
```

2) 특정 GHSA 상세 출력용 (필요시 보강 적용)

```python
class ShowVulnerabilityUseCase:
    def __init__(self, index: VulnerabilityIndexPort, enricher: VulnerabilityEnrichmentPort | None = None) -> None:
        self._index = index
        self._enricher = enricher

    def execute(self, ghsa_id: str) -> Vulnerability | None:
        v = self._index.get_by_ghsa(ghsa_id)
        if v is None:
            return None
        if self._enricher is None:
            return v
        return self._enricher.enrich(v)
```

3) 모든 캐시 삭제

```python
class ClearCacheUseCase:
    def __init__(self, cache: CachePort) -> None:
        self._cache = cache

    def execute(self) -> None:
        self._cache.clear()
```

## Infra 어댑터 개요

- OSV Index (`infra/osv_index.py`)
  - 역할: GHSA 기반 스켈레톤 리스트 반환, 단건 스켈레톤 조회
  - 입력: 로컬 ZIP/디렉토리 파싱 또는 OSV API 호출
  - 출력: `Vulnerability(ghsa_id=..., cve_id=aliases[0], summary, repositories=())`
  - 참고: [docs/osv_구조.md](./osv_구조.md)

- GitHub Enrichment (`infra/github_enrichment.py`)
  - 역할: GraphQL/REST로 Advisory 조회 → 커밋/PoC/레포 메타 정규화
    - URL 파싱 → `(owner, name, commit)` 추출 → `Repository`, `Commit` 구성
    - PoC 키워드 매칭(`poc|exploit|demo|payload|reproduce`) → `poc_urls` 채움
  - 캐싱: CachePort로 응답 캐시 (기본 TTL 30일). 키 포맷 예: `advisory:{ghsa_id}`
  - RateLimit: RateLimiterPort 사용. (권장: 초당 1.5 req REST, 2-3 배치/초 GraphQL)
  - 참고: [docs/github_구조.md](./github_구조.md)

- DiskCache (`infra/cache_diskcache.py`)
  - 역할: `get/set/clear_all` 구현. 디렉토리: `platformdirs` 사용자 캐시 디렉토리 하위 `github/`, `osv/` 등 네임스페이스 분리
  - 직렬화: msgpack/json (바이트 저장). 모델은 외부 레이어에서 직렬화한다.
  - 금지 규칙: import 실패 시 대체 구현(fallback) 금지. 필요 모듈 미설치면 즉시 에러.
  - 리소스 관리: `clear()`로 비우기, `close()`로 종료. 컨텍스트 매니저(with) 지원.

- HTTP Client (`infra/http_client.py`)
  - 역할: 세션 재사용, 헤더(GitHub 토큰), 타임아웃. 응답코드 비정상이면 즉시 예외. JSON은 object만 허용.

## CLI (app/cli.py)

- Typer 기반 단일 엔트리포인트. 출력은 보기 좋게(테이블/하이라이트) 구성하되, 유즈케이스는 도메인 객체만 반환.
- 명령:
  - `cve list --ecosystem npm --limit 50`
  - `cve detail GHSA-xxxx-xxxx-xxxx`
  - `cve clear`
- 설치 및 실행:
  - `pip install -e .` 후 `cve_collector ...` 스크립트 호출 (pyproject `[project.scripts]`).
- 에러 처리: 비정상 상황은 `typer.Exit(code=1)`로 명시 종료. 조용한 fallback 금지.
- 덕타이핑 금지: `Any`, `cast`, `getattr`, `type: ignore` 금지. 출력 함수 시그니처는 구체 타입(`Sequence[Vulnerability]`, `Vulnerability`).

## DI 조립 (dependency-injector)

```python
from dependency_injector import containers, providers
from cve_collector.config.loader import load_config
from cve_collector.config.types import AppConfig
from cve_collector.core.services.composite_enricher import CompositeEnricher
from cve_collector.core.usecases import list_vulnerabilities, show_vulnerability, clear_cache
from cve_collector.infra.cache_diskcache import DiskCacheAdapter
from cve_collector.infra.github_enrichment import GitHubAdvisoryEnricher
from cve_collector.infra.osv_index import OSVIndexAdapter
from cve_collector.infra.rate_limiter import SimpleRateLimiter


def cache_resource(app_cfg: AppConfig):
  with DiskCacheAdapter(namespace="github", default_ttl_seconds=30*24*3600, base_dir=app_cfg.cache_dir) as cache:
    yield cache


class Container(containers.DeclarativeContainer):
  config = providers.Configuration()

  app_config = providers.Callable(load_config)
  cache = providers.Resource(cache_resource, app_config)

  rate_limiter = providers.Factory(SimpleRateLimiter, rps=1.5)
  index = providers.Factory(OSVIndexAdapter, cache=cache)

  enrichers = providers.List(
    providers.Factory(GitHubAdvisoryEnricher, cache=cache),
  )
  composite_enricher = providers.Factory(CompositeEnricher, enrichers=enrichers)

  list_uc = providers.Factory(list_vulnerabilities.ListVulnerabilitiesUseCase, index=index)
  show_uc = providers.Factory(show_vulnerability.ShowVulnerabilityUseCase, index=index, enricher=composite_enricher)
  clear_cache_uc = providers.Factory(clear_cache.ClearCacheUseCase, cache=cache)
```

메모:
- Enricher는 providers.List로 여러 구현을 주입할 수 있고, 필요 시 `ShowVulnerabilityUseCase`에 리스트 자체를 넣는 대신 `CompositeEnricher`를 통해 순차 적용한다.

## 캐시/성능/에러 처리 지침

- 캐시 키: 데이터 소스/엔드포인트/파라미터가 드러나게 구성한다. 예) `osv:list:npm`, `advisory:{ghsa_id}`.
- TTL: GitHub 30일, OSV 7일(권장). CLI 옵션으로 오버라이드 가능.
- 동시성: 초기엔 동기 구현 후, 대용량 처리 시 `ThreadPoolExecutor`로 보강(Enricher의 `enrich_many`).
- 에러 처리: 
  - 404/Null: 존재하지 않는 GHSA는 None 처리, CLI는 친절한 메시지 출력
  - 403: Rate limit 초과 시 대기 또는 즉시 실패 후 재시도 힌트 제공
  - 네트워크: 타임아웃/재시도(지수 백오프) 기본 적용

## 출력 규칙 (app 레벨)

- 리스트: GHSA, CVE(있으면), 주요 레포(`owner/name★stars`), 심각도, 발행일(있으면)
- 단건: 요약, 심각도, 발행/수정일, 레포 목록, 커밋 목록(짧은 해시+URL), PoC 링크
- 컬러링/폭 자르기 등 프리젠테이션은 app에서만 처리하고, core/infra는 관여하지 않는다.

## 마이그레이션 메모

- 기존 `src/cve_collector`는 import하지 않는다. 로직 재사용이 필요하면 개념/파싱 규칙을 문서만 참고한다.
- 단계적 전환 메모는 제거. 본 문서는 `cve` 바이너리를 기준으로 한다.

## 구현 로드맵 (제안)

1. shared/core 뼈대 생성: `domain.models`, `ports`, `usecases`
2. infra 최소 구현: `OSVIndexAdapter`(로컬 파일/한정된 API) → `GitHubAdvisoryEnricher`
3. cache/http/rate_limiter 어댑터 도입 및 DI 연결
4. app/cli 구현: `list`, `show`, `cache clear` 명령
5. 테스트 정비(pyproject의 optional deps 활용), 출력 포맷팅 개선, 동시성 최적화, 캐시 전략 튜닝

---

이 문서는 v2 구현의 기준서이며, 상세 스펙 변경은 본 문서에 누적 기록한다.


