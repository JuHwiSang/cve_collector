"""GitHub API 클라이언트 (Security Advisories 및 Repository 정보)"""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, cast

from pydantic import BaseModel

import httpx
import diskcache as dc
import logging

from cve_collector.utils import RateLimiter, SimpleRateLimiter, helpers, unwrap_nullable
logger = logging.getLogger(__name__)

# Constants
DEFAULT_BATCH_SIZE = 100
DEFAULT_CACHE_TTL = 86400 * 30

@dataclass
class RepositoryInfo:
    """GitHub 저장소 정보"""
    owner: str
    name: str
    size_kb: int
    default_branch: Optional[str] = None
    updated_at: Optional[str] = None
    commit_sha: Optional[str] = None
    commit_message: Optional[str] = None
    commit_date: Optional[str] = None
    commit_author: Optional[str] = None
    
    @property
    def full_name(self) -> str:
        """저장소 풀네임 (owner/name)"""
        return f"{self.owner}/{self.name}"


# ---------------------------------------------------------------------------
# GitHub GraphQL Advisory 모델 (Pydantic)
# ---------------------------------------------------------------------------
"""
GraphQL 쿼리 (securityAdvisory) 응답 예시 (alias: adv1 등)

adv1: securityAdvisory(ghsaId: "GHSA-xxxx-yyyy-zzzz") {
  ghsaId
  summary
  description
  publishedAt
  updatedAt
  severity
  references { url }
  identifiers { type value }
}

본 모델은 위 필드를 그대로 매핑합니다. 일부 필드는 None 가능.
"""

class GHAdvisoryReference(BaseModel):
    url: str


class GHAdvisoryIdentifier(BaseModel):
    type: Optional[str] = None
    value: Optional[str] = None


class GHAdvisoryNode(BaseModel):
    ghsaId: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    publishedAt: Optional[str] = None
    updatedAt: Optional[str] = None
    severity: Optional[str] = None
    references: List[GHAdvisoryReference] = []
    identifiers: List[GHAdvisoryIdentifier] = []


class GitHubClient:
    """GitHub API 클라이언트 (Security Advisories 및 Repository 정보)"""
    
    def __init__(self, rate_limiter: Optional[RateLimiter] = None):
        """
        GitHub API 클라이언트를 초기화합니다.
        
        Args:
            rate_limiter (Optional[RateLimiter]): Rate limiter 인스턴스. None이면 기본값(초당 1.5 요청) 사용
        """
        self.base_url = "https://api.github.com"
        self.graphql_url = "https://api.github.com/graphql"
        self.headers = {
            "Authorization": f"Bearer {unwrap_nullable(os.getenv('GITHUB_TOKEN'))}",
        }
        
        logger.debug("GitHub API 클라이언트 초기화 완료")
        
        self.http_client = httpx.Client(timeout=30, headers=self.headers, follow_redirects=True)
        # GitHub API는 시간당 5000 요청 제한이므로 보수적으로 초당 1.5 요청으로 설정
        self.rate_limiter = rate_limiter or SimpleRateLimiter(requests_per_second=1.5)
        # Instance-level diskcache (path resolved at runtime for testability)
        self.cache_dir = helpers.get_cache_dir() / "github"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache = dc.Cache(str(self.cache_dir))

    def __getstate__(self):
        """
        객체 직렬화(pickling) 시 호출됩니다.
        직렬화할 수 없는 http_client를 제외한 상태를 반환합니다.
        """
        state = self.__dict__.copy()
        state.pop("http_client", None)
        state.pop("_cache", None)
        state.pop("cache_dir", None)
        return state

    def __setstate__(self, state):
        """
        객체 역직렬화(unpickling) 시 호출됩니다.
        상태를 복원하고 http_client를 다시 초기화합니다.
        """
        self.__dict__.update(state)
        self.http_client = httpx.Client(timeout=30, headers=self.headers, follow_redirects=True)
        self.cache_dir = helpers.get_cache_dir() / "github"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache = dc.Cache(str(self.cache_dir))

    def fetch_security_advisory(self, ghsa_id: str) -> Optional[GHAdvisoryNode]:
        """
        단일 GHSA ID의 GitHub Security Advisory 정보를 가져옵니다.
        
        Args:
            ghsa_id (str): GitHub Security Advisory ID (예: "GHSA-xxxx-xxxx-xxxx")
            
        Returns:
            Optional[dict]: Advisory 정보, 존재하지 않으면 None
            
        Note:
            - GitHub REST API 사용: GET /advisories/{ghsa_id}
            - 30일 캐싱 적용 (memoize 데코레이터)
            - Rate limiting 적용
        """
        # cache first
        cache_key = f"advisory:{ghsa_id}"
        try:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cast(GHAdvisoryNode, cached)
        except Exception:
            pass

        self.rate_limiter.wait_if_needed()
        
        response = self.http_client.get(f"{self.base_url}/advisories/{ghsa_id}")
        if response.status_code != 200:
            return None
        
        raw = response.json()
        try:
            node = GHAdvisoryNode.model_validate(raw)
        except Exception:
            node = None
        try:
            self._cache.set(cache_key, node, expire=DEFAULT_CACHE_TTL)
        except Exception:
            pass
        return node

    def fetch_security_advisories_batch(self, ghsa_ids: List[str], batch_size: int = DEFAULT_BATCH_SIZE) -> Dict[str, Optional[GHAdvisoryNode]]:
        """
        여러 GHSA ID의 GitHub Security Advisory 정보를 배치로 가져옵니다.
        
        Args:
            ghsa_ids (List[str]): GHSA ID 리스트
            batch_size (int): 배치 크기 (기본: 50, 권장: 20-50)
            
        Returns:
            Dict[str, Optional[dict]]: {ghsa_id: advisory_data} 형태
            
        Note:
            - GitHub GraphQL API 사용 (alias 활용)
            - 캐시 우선 조회, 캐시에 없는 것만 API 호출
            - Rate limiting 적용 (초당 2-3 배치)
            - 대량 조회시 REST API 대비 90% 시간 단축
        """
        result: Dict[str, Optional[GHAdvisoryNode]] = {}
        uncached_ids = []
        
        # 1단계: 캐시에서 먼저 확인
        for ghsa_id in ghsa_ids:
            cache_key = f"advisory:{ghsa_id}"
            try:
                cached_advisory = self._cache.get(cache_key)
                if cached_advisory is not None:
                    result[ghsa_id] = cast(GHAdvisoryNode, cached_advisory)
                else:
                    uncached_ids.append(ghsa_id)
            except Exception:
                uncached_ids.append(ghsa_id)
        
        if not uncached_ids:
            return result
        
        logger.info(f"캐시되지 않은 {len(uncached_ids)}개 GHSA ID에 대해 GraphQL 배치 조회 시작")
        
        # 2단계: 배치 단위로 GraphQL API 호출
        for i in range(0, len(uncached_ids), batch_size):
            batch_ids = uncached_ids[i:i + batch_size]
            batch_result = self._fetch_batch_graphql(batch_ids)
            
            # 결과 병합 및 캐시 저장
            for ghsa_id, advisory_node in batch_result.items():
                result[ghsa_id] = advisory_node
                cache_key = f"advisory:{ghsa_id}"
                try:
                    self._cache.set(cache_key, advisory_node, expire=DEFAULT_CACHE_TTL)
                except Exception:
                    pass  # 캐시 저장 실패시 무시
        
        return result
    
    def _fetch_batch_graphql(self, ghsa_ids: List[str]) -> Dict[str, Optional[GHAdvisoryNode]]:
        """
        GraphQL을 사용하여 배치로 Advisory를 조회합니다.
        
        Args:
            ghsa_ids (List[str]): 조회할 GHSA ID 리스트 (최대 50개 권장)
            
        Returns:
            Dict[str, Optional[dict]]: {ghsa_id: advisory_data} 형태
        """
        # GraphQL 쿼리 생성 (동적 alias 사용)
        aliases = []
        alias_to_ghsa = {}
        
        for i, ghsa_id in enumerate(ghsa_ids):
            alias = f"adv{i + 1}"
            alias_to_ghsa[alias] = ghsa_id
            aliases.append(f'''
            {alias}: securityAdvisory(ghsaId: "{ghsa_id}") {{
                ghsaId
                summary
                description
                publishedAt
                updatedAt
                severity
                references {{
                    url
                }}
                identifiers {{
                    type
                    value
                }}
            }}''')
        
        query = f"query BatchAdvisories {{{' '.join(aliases)}}}"
        
        # GraphQL API 호출
        self.rate_limiter.wait_if_needed()
        
        headers = self.headers.copy()
        headers["Content-Type"] = "application/json"
        
        logger.debug(f"GraphQL 요청 쿼리 길이: {len(query)}")
        
        response = self.http_client.post(
            self.graphql_url,
            json={"query": query},
            headers=headers
        )
        
        if response.status_code != 200:
            logger.error(f"GraphQL 요청 실패: {response.status_code}")
            return {ghsa_id: None for ghsa_id in ghsa_ids}
        
        # 응답 파싱
        result: Dict[str, Optional[GHAdvisoryNode]] = {}
        response_data = response.json()
        
        logger.debug("GraphQL 응답 수신")
        
        if "data" not in response_data:
            logger.error("GraphQL 응답에 data 필드가 없음")
            return {ghsa_id: None for ghsa_id in ghsa_ids}
        
        # alias를 실제 GHSA ID로 매핑하여 결과 구성 (Pydantic 검증)
        for alias, ghsa_id in alias_to_ghsa.items():
            raw_node = response_data["data"].get(alias)
            try:
                node = GHAdvisoryNode.model_validate(raw_node) if raw_node else None
                result[ghsa_id] = node
            except Exception:
                result[ghsa_id] = None
        
        # 에러 로깅 (GraphQL에서는 일부 실패해도 200 응답)
        if "errors" in response_data:
            logger.warning("GraphQL 부분 에러 포함")
        
        return result

    def is_repository_too_large_at_commit(self, owner: str, repo_name: str, commit_sha: str, max_size_kb: int) -> Optional[bool]:
        """
        특정 커밋 시점의 저장소가 제한 크기를 초과하는지 확인합니다.
        
        알고리즘:
        1. Archive 압축 크기 확인 (빠름)
        2. 압축 크기가 제한 이내라면 Tree API로 정확한 크기 확인
        3. 압축 크기가 제한 초과라면 바로 True 반환
        
        Args:
            owner (str): 저장소 소유자
            repo_name (str): 저장소 이름
            commit_sha (str): 커밋 해시
            max_size_kb (int): 제한 크기 (KB)
        
        Returns:
            Optional[bool]: 제한 초과 여부, 조회 실패시 None
            - True: 제한 크기 초과
            - False: 제한 크기 이내
            - None: 조회 실패 (저장소/커밋 없음)
            
        Example:
            # 10MB 제한으로 체크
            is_too_large = github_client.is_repository_too_large_at_commit(
                "expressjs", "express", "abc123", 10240
            )
            if is_too_large:
                print("저장소가 너무 큽니다")
            elif is_too_large is False:
                print("저장소 크기가 적당합니다")
            else:
                print("조회 실패")
        """
        # Cache first
        size_key = f"repo_too_large:{owner}/{repo_name}@{commit_sha}:{max_size_kb}"
        try:
            cached_result = self._cache.get(size_key)
            if cached_result is not None:
                return cast(bool, cached_result)
        except Exception:
            pass

        # 1단계: Archive 압축 크기 확인 (빠름)
        archive_size = self._get_size_by_archive(owner, repo_name, commit_sha)
        if archive_size is None:
            return None  # 조회 실패
        
        # 2단계: 압축 크기가 제한을 크게 초과하면 바로 True
        if archive_size > max_size_kb:
            logger.info(f"압축 크기 {archive_size} KB가 제한을 초과하여 바로 제한 초과로 판단")
            try:
                self._cache.set(size_key, True, expire=DEFAULT_CACHE_TTL)
            except Exception:
                pass
            return True
        
        # 3단계: 애매한 구간이면 Tree API로 정확한 크기 확인
        logger.info(f"압축 크기 {archive_size} KB, Tree API로 정확한 크기 확인 중...")
        actual_size = self._get_size_by_tree(owner, repo_name, commit_sha)
        if actual_size is None:
            # Tree 조회 실패시 압축 크기 기준으로 보수적 판단
            logger.warning("Tree 조회 실패, 압축 크기 기준으로 판단")
            result = archive_size > max_size_kb // 3  # 압축률 3배 가정
            try:
                self._cache.set(size_key, result, expire=DEFAULT_CACHE_TTL)
            except Exception:
                pass
            return result
        
        logger.info(f"정확한 크기: {actual_size} KB (제한: {max_size_kb} KB)")
        result = actual_size > max_size_kb
        try:
            self._cache.set(size_key, result, expire=DEFAULT_CACHE_TTL)
        except Exception:
            pass
        return result
    
    def _get_size_by_archive(self, owner: str, repo_name: str, commit_sha: str) -> Optional[int]:
        """Archive API를 사용하여 압축 파일 크기 기준으로 저장소 크기를 추정합니다."""
        self.rate_limiter.wait_if_needed()
        
        # HEAD 요청으로 Content-Length만 확인
        response = self.http_client.head(f"{self.base_url}/repos/{owner}/{repo_name}/zipball/{commit_sha}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        
        # Content-Length 헤더에서 압축 파일 크기 (bytes)를 KB로 변환
        content_length = response.headers.get("Content-Length")
        if content_length:
            return int(content_length) // 1024  # bytes to KB
        return None
    
    def _get_size_by_tree(self, owner: str, repo_name: str, commit_sha: str) -> Optional[int]:
        """Git Tree API를 사용하여 실제 파일 크기를 합산합니다."""
        try:
            # 1단계: 커밋에서 tree SHA 얻기
            self.rate_limiter.wait_if_needed()
            commit_response = self.http_client.get(f"{self.base_url}/repos/{owner}/{repo_name}/git/commits/{commit_sha}")
            if commit_response.status_code == 404:
                return None
            commit_response.raise_for_status()
            
            tree_sha = commit_response.json().get("tree", {}).get("sha")
            if not tree_sha:
                return None
            
            # 2단계: Tree API로 모든 파일과 크기 조회
            self.rate_limiter.wait_if_needed()
            tree_response = self.http_client.get(
                f"{self.base_url}/repos/{owner}/{repo_name}/git/trees/{tree_sha}",
                params={"recursive": "1"}
            )
            if tree_response.status_code == 404:
                return None
            tree_response.raise_for_status()
            
            # 3단계: 모든 blob의 크기 합산
            total_size = 0
            tree_data = tree_response.json()
            
            if tree_data.get("truncated"):
                logger.warning("Tree가 잘렸습니다. 부분적인 크기만 반환됩니다.")
            
            for item in tree_data.get("tree", []):
                if item.get("type") == "blob" and "size" in item:
                    total_size += item["size"]  # bytes
            
            return total_size // 1024  # bytes to KB
            
        except Exception as e:
            logger.error(f"Tree 방법으로 크기 조회 실패: {e}")
            return None

    def get_repository_info(self, owner: str, repo_name: str, commit_sha: Optional[str] = None) -> Optional[RepositoryInfo]:
        """
        GitHub 저장소 상세 정보를 가져옵니다.
        
        Args:
            owner (str): 저장소 소유자 (사용자명 또는 조직명)
            repo_name (str): 저장소 이름
            commit_sha (Optional[str]): 특정 커밋 해시 (제공시 커밋 정보도 포함)
            
        Returns:
            Optional[RepositoryInfo]: 저장소 정보 객체, 존재하지 않으면 None
            
        Note:
            - GitHub REST API 사용, 24시간 캐싱 적용
            - 404 에러시 None 반환 (저장소가 비공개이거나 삭제됨)
            - commit_sha 제공시 해당 커밋 정보도 함께 조회 및 캐싱
            - Rate limiting으로 안정적 처리
            
        Example:
            repo_info = github_client.get_repository_info("expressjs", "express")
            if repo_info and repo_info.size_kb > 10240:
                print(f"{repo_info.full_name}: Repository too large to process")
        """
        cache_key = f"repo_info:{owner}/{repo_name}@{commit_sha or 'default'}"
        try:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cast(RepositoryInfo, cached)
        except Exception:
            pass

        self.rate_limiter.wait_if_needed()
        
        # 저장소 기본 정보 조회
        response = self.http_client.get(f"{self.base_url}/repos/{owner}/{repo_name}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        
        repo_data = response.json()
        repo_info = RepositoryInfo(
            owner=owner,
            name=repo_name,
            size_kb=repo_data.get("size"),
            default_branch=repo_data.get("default_branch"),
            updated_at=repo_data.get("updated_at")
        )
        
        # 특정 커밋 정보 조회 (간단하게)
        if commit_sha:
            try:
                self.rate_limiter.wait_if_needed()
                commit_response = self.http_client.get(f"{self.base_url}/repos/{owner}/{repo_name}/commits/{commit_sha}")
                if commit_response.status_code == 200:
                    commit_data = commit_response.json()
                    repo_info.commit_sha = commit_data.get("sha")
                    repo_info.commit_message = commit_data.get("commit", {}).get("message")
                    repo_info.commit_date = commit_data.get("commit", {}).get("committer", {}).get("date")
                    repo_info.commit_author = commit_data.get("commit", {}).get("author", {}).get("name")
            except Exception:
                pass  # 커밋 조회 실패시 무시
        
        try:
            self._cache.set(cache_key, repo_info, expire=DEFAULT_CACHE_TTL)
        except Exception:
            pass
        return repo_info

    def get_repository_sizes_batch(self, repositories: List[tuple], batch_size: int = DEFAULT_BATCH_SIZE) -> Dict[tuple, Optional[int]]:
        """
        여러 GitHub 저장소의 크기를 배치로 가져옵니다.
        
        Args:
            repositories (List[tuple]): [(owner, repo_name), ...] 형태의 저장소 리스트
            batch_size (int): 배치 크기 (기본: 50, 권장: 20-50)
            
        Returns:
            Dict[tuple, Optional[int]]: {(owner, repo_name): disk_usage_kb} 형태
            
        Note:
            - GitHub GraphQL API 사용 (diskUsage 필드)
            - 캐시 우선 조회, 캐시에 없는 것만 API 호출
            - Rate limiting 적용
            - diskUsage는 KB 단위
            - 존재하지 않거나 접근 불가한 저장소는 None
            - 대량 조회시 REST API 대비 효율적
            
        Example:
            repos = [("expressjs", "express"), ("nodejs", "node"), ("microsoft", "vscode")]
            sizes = github_client.get_repository_sizes_batch(repos)
            for (owner, repo), size in sizes.items():
                if size:
                    print(f"{owner}/{repo}: {size} KB")
        """
        result = {}
        uncached_repos = []
        
        if not repositories:
            return result
        
        # 1단계: 캐시에서 먼저 확인
        for repo_tuple in repositories:
            owner, repo_name = repo_tuple
            cache_key = f"repo_size:{owner}/{repo_name}"
            try:
                cached_size = self._cache.get(cache_key)
                if cached_size is not None:
                    result[repo_tuple] = cached_size
                else:
                    uncached_repos.append(repo_tuple)
            except Exception:
                uncached_repos.append(repo_tuple)
        
        if not uncached_repos:
            return result
        
        logger.info(f"캐시되지 않은 {len(uncached_repos)}개 저장소 크기를 GraphQL 배치로 조회 시작")
        
        # 2단계: 배치 단위로 GraphQL API 호출
        for i in range(0, len(uncached_repos), batch_size):
            batch_repos = uncached_repos[i:i + batch_size]
            batch_result = self._fetch_repository_sizes_graphql(batch_repos)
            
            # 결과 병합 및 캐시 저장
            for repo_tuple, size in batch_result.items():
                result[repo_tuple] = size
                owner, repo_name = repo_tuple
                cache_key = f"repo_size:{owner}/{repo_name}"
                try:
                    self._cache.set(cache_key, size, expire=DEFAULT_CACHE_TTL)
                except Exception:
                    pass  # 캐시 저장 실패시 무시
        
        return result
    
    def _fetch_repository_sizes_graphql(self, repositories: List[tuple]) -> Dict[tuple, Optional[int]]:
        """
        GraphQL을 사용하여 배치로 저장소 크기를 조회합니다.
        
        Args:
            repositories (List[tuple]): [(owner, repo_name), ...] 형태 (최대 50개 권장)
            
        Returns:
            Dict[tuple, Optional[int]]: {(owner, repo_name): disk_usage_kb} 형태
        """
        # GraphQL 쿼리 생성 (동적 alias 사용)
        aliases = []
        alias_to_repo = {}
        
        for i, (owner, repo_name) in enumerate(repositories):
            alias = f"R{i + 1}"
            alias_to_repo[alias] = (owner, repo_name)
            aliases.append(f'{alias}: repository(owner: "{owner}", name: "{repo_name}") {{ diskUsage }}')
        
        query = f"query BatchRepositorySizes {{ {' '.join(aliases)} }}"
        
        # GraphQL API 호출
        self.rate_limiter.wait_if_needed()
        
        headers = self.headers.copy()
        headers["Content-Type"] = "application/json"
        
        response = self.http_client.post(
            self.graphql_url,
            json={"query": query},
            headers=headers
        )
        
        if response.status_code != 200:
            logger.error(f"GraphQL 요청 실패: {response.status_code}")
            return {repo: None for repo in repositories}
        
        # 응답 파싱
        result = {}
        response_data = response.json()
        
        if "data" not in response_data:
            logger.error("GraphQL 응답에 data 필드가 없음")
            return {repo: None for repo in repositories}
        
        # alias를 실제 저장소 정보로 매핑하여 결과 구성
        for alias, repo_info in alias_to_repo.items():
            repo_data = response_data["data"].get(alias)
            disk_usage = repo_data.get("diskUsage") if repo_data else None
            result[repo_info] = disk_usage
        
        # 에러 로깅 (GraphQL에서는 일부 실패해도 200 응답)
        if "errors" in response_data:
            logger.warning("GraphQL 부분 에러 포함")
        
        return result

    def clear_cache(self):
        """모든 캐시를 지웁니다."""
        try:
            self._cache.clear(retry=True)
            logger.info("캐시가 성공적으로 지워졌습니다.")
        except Exception as e:
            logger.warning(f"캐시 지우기 실패: {e}")

    def download_patch_file(self, owner: str, repo_name: str, commit_sha: str, destination: Path):
        """
        GitHub에서 특정 커밋의 패치 파일을 다운로드합니다.
        Rate limiting이 적용됩니다.
        
        Args:
            owner (str): 저장소 소유자
            repo_name (str): 저장소 이름  
            commit_sha (str): 커밋 해시 (최소 7자리)
            destination (Path): 저장할 파일 경로
            
        Raises:
            httpx.HTTPStatusError: 다운로드 실패시
            
        Note:
            - GitHub의 .patch 엔드포인트 사용
            - 파일명은 보통 {commit_sha}.patch 형식 권장
            - Rate limiting으로 안정적 다운로드
            
        Example:
            github_client.download_patch_file("expressjs", "express", "abc1234", Path("./abc1234.patch"))
        """
        self.rate_limiter.wait_if_needed()
        patch_url = f"https://raw.githubusercontent.com/{owner}/{repo_name}/{commit_sha}.patch"
        response = self.http_client.get(patch_url)
        response.raise_for_status()
        destination.write_text(response.text) 