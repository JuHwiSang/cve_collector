"""API 요청 rate limiting을 위한 유틸리티"""

import time
from typing import Protocol


class RateLimiter(Protocol):
    """Rate limiter 인터페이스"""
    
    def wait_if_needed(self) -> None:
        """필요시 대기하여 rate limit을 준수합니다."""
        ...


class SimpleRateLimiter:
    """간단한 rate limiter 구현"""
    
    def __init__(self, requests_per_second: float):
        """
        SimpleRateLimiter를 초기화합니다.
        
        Args:
            requests_per_second (float): 초당 허용 요청 수
        """
        self.min_request_interval = 1.0 / requests_per_second
        self.last_request_time = 0.0
    
    def wait_if_needed(self) -> None:
        """필요시 대기하여 rate limit을 준수합니다."""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        
        if time_since_last_request < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last_request
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()


class NoRateLimiter:
    """Rate limiting을 하지 않는 더미 구현"""
    
    def wait_if_needed(self) -> None:
        """아무것도 하지 않습니다."""
        pass 