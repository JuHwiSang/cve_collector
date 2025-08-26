"""OSV (Open Source Vulnerability) API 클라이언트

OSV 응답 형식 개요
-------------------
OSV의 단일 취약점 레코드(예: GET /v1/vulns/{ID})는 대략 다음과 같은 스키마를 가집니다.

예시 (필수/주요 필드 위주, 일부 생략/축약):

{
  "id": "GHSA-xxxx-yyyy-zzzz",              # OSV 고유 ID (GHSA-*, CVE-*, MAL-*, GSD-*)
  "published": "2024-01-01T12:34:56Z",      # 최초 공개 시각 (ISO8601)
  "modified": "2024-02-01T00:00:00Z",       # 최근 수정 시각 (ISO8601)
  "aliases": ["CVE-2024-1234"],              # 다른 식별자들(CVE 등)
  "summary": "Short human-readable title",   # 요약 제목
  "details": "Longer markdown/plain details", # 상세 설명(마크다운 가능)
  "severity": [                               # 선택: 심각도 목록
    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."}
  ],
  "affected": [                               # 영향을 받는 패키지 목록
    {
      "package": {
        "ecosystem": "npm",                 # 예: npm, PyPI, Maven 등
        "name": "express",                  # 패키지 이름
        "purl": "pkg:npm/express"          # 선택: purl
      },
      "ranges": [                            # 버전 범위(여러 타입 가능: SEMVER/ECOSYSTEM/GIT)
        {
          "type": "SEMVER",
          "events": [
            {"introduced": "4.0.0"},
            {"fixed": "4.18.3"}
          ]
        }
      ],
      "versions": ["4.0.0", "4.18.2"],    # 선택: 영향받는 구체 버전 나열
      "database_specific": { ... }           # 레지스트리 특화 메타데이터
    }
  ],
  "references": [                            # 참고 링크들
    {"type": "ADVISORY", "url": "https://.../CVE-2024-1234"},
    {"type": "WEB", "url": "https://blog/..."},
    {"type": "FIX", "url": "https://github.com/owner/repo/commit/<sha>"}
  ],
  "schema_version": "1.7.3"                  # 스키마 버전
}

추가 엔드포인트
----------------
1) POST /v1/query
   - 바디에 {"package": {"name": "lodash", "ecosystem": "npm"}}처럼 전달하면,
     해당 패키지에 대한 취약점 리스트를 {"vulns": [ ...OSV 레코드... ]} 형태로 반환합니다.

2) all.zip (대용량 데이터셋)
   - 생태계별 전체 취약점 데이터가 개별 JSON 파일로 압축되어 있으며,
     각 파일의 내용은 단일 레코드 스키마와 동일합니다.

본 모듈에서 활용하는 주요 필드
--------------------------------
- "published" (날짜 필터, 기본 발행일)
- "aliases" (CVE ID 추출에 사용)
- "affected[*].package.ecosystem/name/purl" (생태계/패키지 정보)
- "references[*].url" (커밋/패치/PoC 링크 추출의 근거)
- "severity" (필요 시 심각도 표시/분류에 활용 가능)
"""

import json
import shutil
from pathlib import Path
from typing import Dict, List, Optional

import httpx
import logging

from cve_collector.utils import RateLimiter, SimpleRateLimiter, helpers
logger = logging.getLogger(__name__)


class OSVClient:
    """OSV (Open Source Vulnerability) API 클라이언트"""
    
    def __init__(self, rate_limiter: Optional[RateLimiter] = None):
        """
        OSV API 클라이언트를 초기화합니다.
        
        Args:
            rate_limiter (Optional[RateLimiter]): Rate limiter 인스턴스. None이면 기본값(초당 12 요청) 사용
        """
        self.base_url = "https://api.osv.dev/v1"
        self.http_client = httpx.Client(timeout=30)
        self.rate_limiter = rate_limiter or SimpleRateLimiter(requests_per_second=12.0)
    
    def _rate_limit(self):
        """Rate limiting을 적용합니다. (API 호출용)"""
        self.rate_limiter.wait_if_needed()
    
    def _download_vulnerability_database(self) -> Path:
        """
        OSV 데이터베이스를 다운로드하고 압축을 해제합니다. (내부 사용)
        
        Returns:
            Path: 압축 해제된 디렉토리 경로
        """
        zip_url = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
        cache_dir = helpers.get_cache_dir()
        zip_path = cache_dir / "npm_all.zip"
        extract_dir = cache_dir / "osv_npm"
        
        if not extract_dir.exists():  # 압축 해제된 디렉토리가 없으면 다운로드
            logger.info("OSV 데이터베이스 다운로드 중...")
            response = self.http_client.get(zip_url, follow_redirects=True)
            response.raise_for_status()
            zip_path.write_bytes(response.content)
            
            logger.info("OSV 데이터베이스 압축 해제 중...")
            shutil.unpack_archive(zip_path, extract_dir)
            
            # ZIP 파일 삭제 (디스크 공간 절약)
            zip_path.unlink()
            logger.info("ZIP 파일 삭제 완료 (디스크 공간 절약)")
        else:
            logger.info("이미 다운로드된 OSV 데이터를 사용합니다.")
        
        return extract_dir

    def get_all_npm_vulnerabilities(self, vuln_type: Optional[str] = None) -> Dict[str, dict]:
        """
        모든 npm 생태계 취약점 데이터를 가져옵니다.
        
        OSV 데이터베이스를 다운로드하고 모든 취약점 파일을 읽어서
        취약점 ID를 키로 하는 딕셔너리를 반환합니다.
        
        Args:
            vuln_type (Optional[str]): 필터링할 취약점 타입 (예: "GHSA", "MAL", "GSD")
                                     None이면 모든 타입 포함
        
        Returns:
            Dict[str, dict]: 취약점 ID를 키로 하는 취약점 데이터 딕셔너리
            
        Note:
            - 첫 실행시에만 다운로드하고, 이후에는 캐시된 파일 사용
            - ZIP 파일은 압축 해제 후 자동 삭제
            - vuln_type 지정시 해당 타입만 처리 (성능 향상)
            - 대용량 JSON 파일 처리로 Progress bar 표시
            
        Example:
            # 모든 취약점 가져오기
            all_vulns = osv_client.get_all_npm_vulnerabilities()
            
            # GHSA 취약점만 가져오기
            ghsa_vulns = osv_client.get_all_npm_vulnerabilities(vuln_type="GHSA")
        """
        extract_dir = self._download_vulnerability_database()
        
        vulnerabilities = {}
        json_files = list(extract_dir.glob("*.json"))
        
        # 타입 필터링
        if vuln_type:
            json_files = [f for f in json_files if f.stem.startswith(vuln_type)]
            logger.info(f"{vuln_type} 타입 필터 적용: {len(json_files)}개 파일 처리 예정")
        else:
            logger.info(f"총 {len(json_files)}개 취약점 파일 처리 예정")
        
        for vuln_file in json_files:
            try:
                vuln_data = json.loads(vuln_file.read_text(encoding="utf-8"))
                vulnerabilities[vuln_file.stem] = vuln_data
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.warning(f"파일 {vuln_file.name} 읽기 오류: {e}")
                continue
        
        logger.info(f"{len(vulnerabilities)}개 취약점 데이터 로딩 완료")
        return vulnerabilities

    def fetch_package_vulnerabilities(self, package_name: str) -> List[dict]:
        """
        특정 npm 패키지의 모든 취약점 정보를 OSV API로부터 가져옵니다.
        Rate limiting이 적용됩니다.
        
        Args:
            package_name (str): npm 패키지 이름 (예: "express", "lodash")
            
        Returns:
            List[dict]: 해당 패키지의 취약점 정보 리스트
            
        Raises:
            httpx.HTTPStatusError: API 호출 실패시
            
        Example:
            vulns = osv_client.fetch_package_vulnerabilities("express")
            print(f"Found {len(vulns)} vulnerabilities for express")
        """
        self._rate_limit()
        response = self.http_client.post(
            f"{self.base_url}/query", 
            json={"package": {"name": package_name, "ecosystem": "npm"}}
        )
        response.raise_for_status()
        return response.json().get("vulns", [])

    def fetch_vulnerability_details(self, vulnerability_id: str) -> dict:
        """
        단일 취약점 ID의 상세 정보를 OSV API로부터 가져옵니다.
        Rate limiting이 적용됩니다.
        
        Args:
            vulnerability_id (str): 취약점 식별자 (예: "CVE-2024-1234", "GHSA-xxxx-xxxx-xxxx")
            
        Returns:
            dict: 취약점의 상세 정보 (OSV 스키마 형식)
            
        Raises:
            httpx.HTTPStatusError: API 호출 실패시 (404: 취약점 없음)
            
        Example:
            vuln_data = osv_client.fetch_vulnerability_details("CVE-2024-1234")
            print(vuln_data['summary'])
        """
        self._rate_limit()
        response = self.http_client.get(f"{self.base_url}/vulns/{vulnerability_id}")
        response.raise_for_status()
        return response.json() 