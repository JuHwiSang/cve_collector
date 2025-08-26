"""CVE 메타데이터 및 패치 정보를 수집하는 메인 클래스"""

import json
import os
import re
from dataclasses import asdict
from datetime import date
from pathlib import Path
from typing import List, Optional

import logging
import diskcache as dc

from cve_collector.core.github_client import GitHubClient
from cve_collector.core.osv_client import OSVClient
from cve_collector.cve import CVE
from cve_collector.utils import helpers

# Constants
POC_RE = re.compile(r"(poc|exploit|demo|payload|reproduce)", re.I)

# Logger
logger = logging.getLogger(__name__)


class PostFilterError(Exception):
    """Raised when a CVE fails the post-filter criteria.

    Attributes:
        code: Machine-readable reason code (e.g., "no_repo", "repo_large", "no_artifacts").
        message: Human-readable description.
    """
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class CVECollector:
    """CVE 메타데이터 및 패치 정보를 수집하는 메인 클래스"""
    
    def __init__(self, github_token: str):
        self.osv_client = OSVClient()
        self.github_client = GitHubClient(github_token)
    
    @staticmethod
    def get_meta_path() -> Path:
        """전체 CVE 메타데이터 파일 경로를 반환합니다."""
        return helpers.get_data_dir() / "cve-meta.json"
    
    # 내부 전용: OSV 후보 로딩 (BWC를 위해 공개 메서드 유지)
    def _load_osv_candidates(self) -> List[CVE]:
        """OSV 데이터셋(전체)에서 GHSA 취약점을 읽어 CVE 객체로 변환합니다."""
        logger.info("CVE 데이터를 수집합니다")

        # GHSA 취약점만 가져오기 (OSVClient에서 필터링)
        logger.info("OSV에서 GHSA 취약점 데이터를 로딩합니다")
        ghsa_vulnerabilities = self.osv_client.get_all_npm_vulnerabilities(vuln_type="GHSA")

        # 모든 GHSA 데이터를 CVE 객체로 변환
        all_cves: List[CVE] = []
        for ghsa_id, vulnerability_data in ghsa_vulnerabilities.items():
            cve = CVE.from_osv_data(ghsa_id, vulnerability_data)
            all_cves.append(cve)

        logger.info(f"총 {len(all_cves)}개 GHSA 데이터를 CVE 객체로 변환했습니다")

        return all_cves

    
    
    def _apply_pre_filters(
        self,
        cves: List[CVE],
        since_date: Optional[date] = None,
        allowed_identifiers: Optional[set[str]] = None,
    ) -> List[CVE]:
        """GitHub API 호출 이전 기본 필터링을 적용합니다.

        Args:
            cves: 필터링 대상 CVE 목록
            since_date: 발행일 필터 기준 (해당 날짜 이전은 제외)
            allowed_identifiers: 식별자 화이트리스트 (CVE 또는 GHSA). 지정 시 목록에 포함된 항목만 통과

        Returns:
            List[CVE]: 기본 필터를 통과한 목록
        """
        filtered = []
        
        # 통계 카운터
        stats = {
            "total": len(cves),
            "filtered_no_npm": 0,
            "filtered_no_cve_id": 0,
            "filtered_date": 0,
            "filtered_identifier": 0,
            "passed": 0
        }
        
        for cve in cves:
            # 식별자 필터링 (CVE ID 또는 GHSA ID가 allowed_identifiers에 포함되어야 함)
            if allowed_identifiers is not None:
                id_matched = (cve.cve_id in allowed_identifiers) or (cve.ghsa_id in allowed_identifiers)
                if not id_matched:
                    stats["filtered_identifier"] += 1
                    continue
            # npm 생태계 필터링
            if "npm" not in cve.affected_ecosystems:
                stats["filtered_no_npm"] += 1
                continue
            
            # CVE ID 필터링 (전체 수집시에만 CVE ID 강제)
            if not cve.cve_id and allowed_identifiers is None:
                stats["filtered_no_cve_id"] += 1
                continue
            
            # 날짜 필터링
            if since_date and cve.published_date < since_date:
                stats["filtered_date"] += 1
                continue
            
            filtered.append(cve)
            stats["passed"] += 1
        
        # 필터링 통계 출력
        self._print_filter_stats(stats, "기본 필터링")
        
        return filtered
    
    def _apply_post_filters(self, cves: List[CVE]) -> List[CVE]:
        """GitHub 보강 이후 상세 필터링을 적용합니다.

        Criteria:
            - repo 미존재 제외
            - 저장소 크기 초과 제외(>10MB)
            - patches/pocs 모두 비어있으면 제외

        Returns:
            List[CVE]: 상세 필터를 통과한 최종 후보
        """
        filtered = []
        max_repo_size_kb = 10240  # 10MB 제한
        
        # 통계 카운터
        stats = {
            "total": len(cves),
            "filtered_no_repo": 0,
            "filtered_repo_large": 0,
            "filtered_repo_error": 0,
            "filtered_no_artifacts": 0,
            "passed": 0
        }
        
        for cve in cves:
            try:
                self._apply_post_filter(cve, max_repo_size_kb=max_repo_size_kb)
                filtered.append(cve)
                stats["passed"] += 1
            except PostFilterError as e:
                if e.code == "no_repo":
                    stats["filtered_no_repo"] += 1
                elif e.code == "repo_large":
                    stats["filtered_repo_large"] += 1
                elif e.code == "no_artifacts":
                    stats["filtered_no_artifacts"] += 1
                else:
                    stats["filtered_repo_error"] += 1
        
        # 필터링 통계 출력
        self._print_filter_stats(stats, "상세 필터링")
        
        return filtered

    def _apply_post_filter(self, cve: CVE, *, max_repo_size_kb: int = 10240) -> CVE:
        """단일 CVE에 대해 상세 필터를 적용합니다. 조건 불만족 시 PostFilterError를 발생시킵니다.

        Raises:
            PostFilterError: 사유 코드는 [no_repo, repo_large, no_artifacts]
        """
        # 저장소 유무
        if not cve.repo:
            raise PostFilterError("no_repo", "저장소 정보 없음")
        # 저장소 크기
        if cve.size_kb and cve.size_kb > max_repo_size_kb:
            raise PostFilterError("repo_large", f"저장소 크기 초과: {cve.size_kb}KB > {max_repo_size_kb}KB")
        # 아티팩트 존재 여부
        if not cve.patches and not cve.pocs:
            raise PostFilterError("no_artifacts", "패치/PoC 없음")
        return cve
    
    def _print_filter_stats(self, stats: dict, stage_name: str):
        """필터링 통계를 출력합니다."""
        total = stats["total"]
        passed = stats["passed"]
        
        logger.info(f"{stage_name} 통계:")
        logger.info(f"  총 CVE: {total:,}개")
        logger.info(f"  통과: {passed:,}개 ({passed/total*100:.1f}%)")
        logger.info(f"  필터링됨: {total-passed:,}개 ({(total-passed)/total*100:.1f}%)")
        
        if stats.get("filtered_no_npm", 0) > 0:
            logger.info(f"    - npm 생태계 아님: {stats['filtered_no_npm']:,}개")
        if stats.get("filtered_no_cve_id", 0) > 0:
            logger.info(f"    - CVE ID 없음: {stats['filtered_no_cve_id']:,}개")
        if stats.get("filtered_date", 0) > 0:
            logger.info(f"    - 날짜 조건: {stats['filtered_date']:,}개")
        if stats.get("filtered_repo_large", 0) > 0:
            logger.info(f"    - 저장소 크기 초과 (>10MB): {stats['filtered_repo_large']:,}개")
        if stats.get("filtered_repo_error", 0) > 0:
            logger.info(f"    - 저장소 조회 오류: {stats['filtered_repo_error']:,}개")
        if stats.get("filtered_no_repo", 0) > 0:
            logger.info(f"    - 저장소 정보 없음: {stats['filtered_no_repo']:,}개")
        if stats.get("filtered_no_artifacts", 0) > 0:
            logger.info(f"    - 패치/PoC 없음: {stats['filtered_no_artifacts']:,}개")
            
    # 내부 전용: GHSA 보강 (BWC를 위해 공개 메서드 유지)
    def _enrich_from_github_advisories(self, cve_candidates: List[CVE]) -> List[CVE]:
        """GitHub Security Advisory 정보로 CVE 데이터를 보강합니다."""

        # GHSA ID 목록 추출
        ghsa_ids = [cve.ghsa_id for cve in cve_candidates if cve.ghsa_id]
        logger.info(f"GitHub API에서 {len(ghsa_ids)}개 Advisory를 배치 조회로 가져옵니다")

        # 배치로 GitHub Advisory 정보 가져오기
        advisory_data_map = self.github_client.fetch_security_advisories_batch(ghsa_ids, batch_size=50)

        # CVE 객체에 Advisory 정보 적용
        logger.info("Advisory 데이터로 CVE 정보를 보강합니다")

        for cve_candidate in cve_candidates:
            # 배치 조회 결과에서 해당 Advisory 데이터 가져오기
            advisory_data = advisory_data_map.get(cve_candidate.ghsa_id)

            if advisory_data:
                try:
                    cve_candidate.gh = advisory_data.model_dump()
                    references = advisory_data.references or []
                    for ref in references:
                        reference_url = ref.url
                        if not reference_url:
                            continue
                        if "/commit/" in reference_url and not reference_url.endswith(".patch"):
                            cve_candidate.patches.append(reference_url)
                        if POC_RE.search(reference_url):
                            cve_candidate.pocs.append(reference_url)
                except Exception:
                    pass

                # repo + commit 추출
                if cve_candidate.patches:
                    commit_match = re.search(r"github.com/([^/]+/[^/]+)/commit/(\w{7,40})", cve_candidate.patches[0])
                    if commit_match:
                        cve_candidate.repo = commit_match.group(1)
                        if cve_candidate.repo:
                            cve_candidate.commits = [commit_match.group(2)]
                            repo_info = self.github_client.get_repository_info(*cve_candidate.repo.split("/", 1))
                            if repo_info:
                                cve_candidate.size_kb = repo_info.size_kb

        logger.info("GitHub Advisory 조회 및 CVE 보강 완료")
        return cve_candidates

    
    
    # 내부 전용: 저장 (BWC를 위해 공개 메서드 유지)
    def _persist_artifacts(self, cve_candidates: List[CVE]) -> None:
        """CVE 메타데이터와 관련 파일들을 저장합니다."""
        logger.info("CVE 메타데이터를 저장합니다")

        # JSON 메타데이터 저장
        json_data = []
        data_dir = helpers.get_data_dir()
        json_path = CVECollector.get_meta_path()
        for cve_candidate in cve_candidates:
            # 각 CVE의 상태 정보 추가
            cve_data = asdict(cve_candidate)
            # 상태 결정: repo 크기에 따라 처리 가능 여부 판단
            if (cve_candidate.size_kb or 0) > 10_240:
                cve_data["status"] = "repo_large"
            elif not cve_candidate.patches and not cve_candidate.pocs:
                cve_data["status"] = "no_artifacts"
            else:
                cve_data["status"] = "ready"

            json_data.append(cve_data)

            # 개별 CVE 디렉토리 및 info.json 저장
            cve_candidate.save()

        # 전체 CVE 메타데이터를 JSON 파일로 저장
        data_dir.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(json_data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

        logger.info("CVE 메타데이터 저장 완료")
        logger.info(f"- 전체 메타데이터: {json_path}")
        logger.info("- 개별 CVE 정보: 각 CVE-*/info.json")

    
    
    # 새 퍼블릭 API -----------------------------------------------------------
    def collect(self, since: Optional[str] = None, identifiers: Optional[List[str]] = None) -> List[CVE]:
        """여러 개의 취약점 메타데이터를 수집하여 저장하고 반환합니다."""

        since_date = date.fromisoformat(since) if since else None

        # 1) CVE 후보 수집 (원시 데이터)
        all_cves = self._load_osv_candidates()
        allowed = set(identifiers) if identifiers else None
        pre_filtered_cves = self._apply_pre_filters(all_cves, since_date, allowed_identifiers=allowed)

        # 2) GitHub advisory 보강
        enriched_candidates = self._enrich_from_github_advisories(pre_filtered_cves)
        logger.debug(f"enriched_candidates: {enriched_candidates}")

        # 3) 상세 필터링 (GitHub 데이터 기반)
        final_candidates = self._apply_post_filters(enriched_candidates)

        # 4) 결과물 저장
        self._persist_artifacts(final_candidates)

        logger.info("collect 단계 완료")
        return final_candidates

    def collect_identifiers(self, since: Optional[str] = None, identifiers: Optional[List[str]] = None) -> List[str]:
        """최종 사용 가능한 취약점 식별자(가능하면 GHSA, 없으면 CVE) 목록을 반환합니다.

        수집 파이프라인은 그대로 수행되며, 메타데이터 저장도 동일하게 이뤄집니다.
        """
        final_candidates = self.collect(since=since, identifiers=identifiers)
        id_list: List[str] = []
        for c in final_candidates:
            ident = c.ghsa_id or c.cve_id
            if ident:
                id_list.append(ident)
        return id_list

    def collect_one(self, identifier: str) -> CVE:
        """단 하나의 CVE/GHSA 식별자만 수집하고 반환합니다.

        파이프라인: OSV 단건 조회 → CVE 변환 → 기본 필터 → GH 보강 → 상세 필터 → 저장 → 반환

        Args:
            identifier: CVE-* 또는 GHSA-* 형식의 식별자

        Returns:
            CVE: 최종 필터를 통과한 해당 CVE 객체

        Raises:
            ValueError: OSV 조회 실패, 기본/상세 필터에서 제외되는 경우 등
        """
        # 1) OSV 단건 조회
        try:
            osv_data = self.osv_client.fetch_vulnerability_details(identifier)
        except Exception as e:
            raise ValueError(f"OSV 조회 실패: {identifier}: {e}")

        # 2) GHSA ID 결정 (입력이 CVE인 경우 aliases에서 GHSA를 시도)
        ghsa_id = identifier
        if not identifier.upper().startswith("GHSA-"):
            ghsa_alias = next((a for a in osv_data.get("aliases", []) if a.startswith("GHSA-")), None)
            if ghsa_alias:
                ghsa_id = ghsa_alias

        # 3) CVE 객체 변환
        cve_obj = CVE.from_osv_data(ghsa_id, osv_data)

        # 4) 기본 필터 (식별자 강제 통과 외 나머지 조건 적용)
        pre_filtered = self._apply_pre_filters([cve_obj], since_date=None, allowed_identifiers={identifier})
        if not pre_filtered:
            raise ValueError("기본 필터에서 제외되었습니다 (npm 아님/날짜 조건/CVE 없음 등)")

        # 5) GitHub 보강
        enriched = self._enrich_from_github_advisories(pre_filtered)

        # 6) 상세 필터
        try:
            self._apply_post_filter(enriched[0])
        except PostFilterError as e:
            raise ValueError(f"상세 필터에서 제외되었습니다: {e.code}: {e}")

        # 7) 저장 및 반환
        self._persist_artifacts([enriched[0]])
        return enriched[0]

    # 하위호환용 래퍼 ---------------------------------------------------------
    

    # 하우스키핑 --------------------------------------------------------------
    @staticmethod
    def clear_local_state() -> tuple[int, int]:
        """디스크 캐시와 최상위 메타데이터 파일을 안전하게 정리합니다.

        Returns:
            (cache_entries_removed, data_items_removed)
        """
        cache_base = helpers.get_cache_dir()
        data_dir = helpers.get_data_dir()

        total_removed = 0
        if cache_base.exists():
            for name in os.listdir(cache_base):
                subdir = cache_base / name
                if not subdir.is_dir():
                    continue
                # Open each subdir as a diskcache Cache and clear safely
                try:
                    c = dc.Cache(str(subdir), timeout=1)
                except Exception:
                    continue
                try:
                    removed = c.clear(retry=True)
                    try:
                        total_removed += int(removed or 0)
                    except Exception:
                        pass
                finally:
                    try:
                        c.close()
                    except Exception:
                        pass

        # Remove only files at top-level of data_dir; keep directories intact
        data_removed = 0
        if data_dir.exists():
            for name in os.listdir(data_dir):
                target = data_dir / name
                if target.is_dir():
                    continue
                try:
                    target.unlink(missing_ok=True)
                    data_removed += 1
                except Exception:
                    pass

        return total_removed, data_removed