"""CVE 데이터 모델 및 관련 유틸리티"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import date
import re
from pathlib import Path
from cve_collector.utils import helpers
from typing import Optional, List

# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CVE:
    """CVE 취약점 정보를 담는 데이터 클래스"""
    ghsa_id: str
    cve_id: Optional[str]
    pkg: Optional[str]
    osv: dict
    published_date: date
    affected_ecosystems: List[str]
    gh: Optional[dict] = None
    repo: Optional[str] = None  # owner/name
    size_kb: Optional[int] = None
    patches: list[str] = field(default_factory=list)
    pocs: list[str] = field(default_factory=list)
    commits: list[str] = field(default_factory=list)

    @property
    def dir(self) -> Path:
        """CVE 정보를 저장할 디렉터리 경로를 반환합니다."""
        if self.cve_id:
            # CVE ID가 있는 경우: data/CVE-YYYY-NNNN 형식 사용 (기획안 준수)
            return helpers.get_data_dir() / self.cve_id
        else:
            return helpers.get_data_dir() / self.ghsa_id

    def save(self):
        """CVE 정보를 JSON 파일로 저장합니다."""
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "info.json").write_text(json.dumps(asdict(self), indent=2, default=str), encoding='utf-8')

    @staticmethod
    def from_osv_data(ghsa_id: str, vulnerability_data: dict) -> 'CVE':
        """
        OSV 취약점 데이터에서 CVE 객체를 생성합니다.
        
        모든 필터링은 외부에서 처리하고, 이 메서드는 순수하게 데이터 변환만 수행합니다.
        
        Args:
            ghsa_id (str): GHSA 취약점 ID (GHSA-xxxx-xxxx-xxxx)
            vulnerability_data (dict): OSV 취약점 데이터
            
        Returns:
            Optional[CVE]: 변환된 CVE 객체, 변환 실패시 None
            
        Note:
            - 필터링 로직 없음 (모든 데이터 포함)
            - CVE ID가 없어도 처리 (cve_id는 Optional)
            - 패키지 이름이 없어도 처리 (pkg는 Optional)
            - 생태계 정보도 포함
            - 날짜 필터링은 외부에서 처리
        """
        # 발행 날짜 추출 (published가 없으면 modified, 그마저 없으면 오늘로 대체)
        published_iso = vulnerability_data.get("published") or vulnerability_data.get("modified") or date.today().isoformat()
        try:
            published_date = date.fromisoformat(published_iso[:10])
        except Exception:
            published_date = date.today()
        
        # CVE ID 추출 (없을 수도 있음)
        cve_id = next((alias for alias in vulnerability_data.get("aliases", []) if alias.startswith("CVE")), None)
        
        # 영향받는 생태계 목록 추출
        affected_packages = vulnerability_data.get("affected", [])
        affected_ecosystems = list(set(
            pkg.get("package", {}).get("ecosystem") 
            for pkg in affected_packages 
            if pkg.get("package", {}).get("ecosystem")
        ))
        
        # 첫 번째 패키지를 대표 패키지로 사용하되 npm을 우선 (없으면 None)
        package_name = None
        if affected_packages:
            npm_pkgs = [p.get("package", {}) for p in affected_packages if p.get("package", {}).get("ecosystem") == "npm"]
            chosen = (npm_pkgs[0] if npm_pkgs else affected_packages[0].get("package", {}))
            package_name = chosen.get("name") or None

        # OSV references에서 기본 아티팩트 추출 (PoC/패치/커밋/리포)
        patches: list[str] = []
        pocs: list[str] = []
        commits: list[str] = []
        repo: Optional[str] = None

        poc_re = re.compile(r"(poc|exploit|demo|payload|reproduce)", re.I)
        commit_re = re.compile(r"github\.com/([^/]+/[^/]+)/commit/([0-9a-fA-F]{7,40})")
        for ref in vulnerability_data.get("references", []) or []:
            url = ref.get("url") or ""
            if not url:
                continue
            # PoC URL 수집
            if poc_re.search(url):
                pocs.append(url)
            # 커밋/패치 링크 수집 및 repo/commit 추출
            m = commit_re.search(url)
            if m:
                if not repo:
                    repo = m.group(1)
                commit_sha = m.group(2)
                commits.append(commit_sha)
                # .patch 확장자 없어도 패치 링크로 간주
                patches.append(url)
            
        # commit_sha = None
        # if repo:
        #     for ref in refs:
        #         if ref.get("type") == "WEB" and ref.get("url").startswith(f"https://github.com/{repo}"):
        #             commit_sha = ref.get("url").split("/")[-1]
        #             break
        
        return CVE(
            ghsa_id=ghsa_id,
            cve_id=cve_id,
            pkg=package_name,
            osv=vulnerability_data,
            published_date=published_date,
            affected_ecosystems=affected_ecosystems,
            repo=repo,
            patches=patches,
            pocs=pocs,
            commits=commits,
        )