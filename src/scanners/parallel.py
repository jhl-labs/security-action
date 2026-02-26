"""병렬 스캐너 실행"""

import asyncio
import concurrent.futures
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from .base import ScanResult
from .code_scanner import CodeScanner
from .dependency_scanner import DependencyScanner
from .secret_scanner import SecretScanner

console = Console()


@dataclass
class ScannerTask:
    """스캐너 태스크"""

    name: str
    scanner_class: type
    enabled: bool = True
    config: dict | None = None


class ParallelScanner:
    """병렬 스캐너 실행기"""

    def __init__(self, workspace: str, max_workers: int = 3):
        self.workspace = workspace
        self.max_workers = max_workers
        self.tasks: list[ScannerTask] = []

    def add_scanner(
        self,
        name: str,
        scanner_class: type,
        enabled: bool = True,
        config: dict | None = None,
    ) -> None:
        """스캐너 추가"""
        self.tasks.append(
            ScannerTask(
                name=name,
                scanner_class=scanner_class,
                enabled=enabled,
                config=config,
            )
        )

    def add_default_scanners(
        self,
        secret_scan: bool = True,
        code_scan: bool = True,
        dependency_scan: bool = True,
    ) -> None:
        """기본 스캐너 추가"""
        self.add_scanner("Gitleaks", SecretScanner, secret_scan)
        self.add_scanner("Semgrep", CodeScanner, code_scan)
        self.add_scanner("Trivy", DependencyScanner, dependency_scan)

    def _run_scanner(self, task: ScannerTask) -> ScanResult:
        """개별 스캐너 실행"""
        try:
            scanner_kwargs = task.config or {}
            scanner = task.scanner_class(self.workspace, **scanner_kwargs)
            return scanner.scan()
        except Exception as e:
            return ScanResult(
                scanner=task.name,
                success=False,
                error=str(e),
            )

    def run_sequential(self) -> list[ScanResult]:
        """순차 실행"""
        results = []
        enabled_tasks = [t for t in self.tasks if t.enabled]

        for task in enabled_tasks:
            console.print(f"[cyan]Running {task.name}...[/cyan]")
            result = self._run_scanner(task)
            results.append(result)
            status = "[green]✓[/green]" if result.success else "[red]✗[/red]"
            console.print(
                f"  {status} {task.name}: {len(result.findings)} findings ({result.execution_time:.2f}s)"
            )

        return results

    def run_parallel(self, show_progress: bool = True) -> list[ScanResult]:
        """병렬 실행"""
        enabled_tasks = [t for t in self.tasks if t.enabled]

        if not enabled_tasks:
            return []

        results: list[ScanResult] = []

        if show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task_ids = {
                    task.name: progress.add_task(f"[cyan]{task.name}[/cyan]", total=None)
                    for task in enabled_tasks
                }

                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.max_workers
                ) as executor:
                    future_to_task = {
                        executor.submit(self._run_scanner, task): task for task in enabled_tasks
                    }

                    for future in concurrent.futures.as_completed(future_to_task):
                        task = future_to_task[future]
                        try:
                            result = future.result()
                            results.append(result)

                            status = "[green]✓[/green]" if result.success else "[red]✗[/red]"
                            progress.update(
                                task_ids[task.name],
                                description=f"{status} {task.name}: {len(result.findings)} findings",
                                completed=True,
                            )
                        except Exception as e:
                            results.append(
                                ScanResult(
                                    scanner=task.name,
                                    success=False,
                                    error=str(e),
                                )
                            )
                            progress.update(
                                task_ids[task.name],
                                description=f"[red]✗[/red] {task.name}: Error",
                                completed=True,
                            )
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_task = {
                    executor.submit(self._run_scanner, task): task for task in enabled_tasks
                }

                for future in concurrent.futures.as_completed(future_to_task):
                    task = future_to_task[future]
                    try:
                        results.append(future.result())
                    except Exception as e:
                        results.append(
                            ScanResult(
                                scanner=task.name,
                                success=False,
                                error=str(e),
                            )
                        )

        # 원래 순서대로 정렬
        task_order = {t.name: i for i, t in enumerate(enabled_tasks)}
        results.sort(key=lambda r: task_order.get(r.scanner, 999))

        return results

    async def run_async(self) -> list[ScanResult]:
        """비동기 실행 (asyncio)"""
        enabled_tasks = [t for t in self.tasks if t.enabled]
        loop = asyncio.get_event_loop()

        async def run_in_executor(task: ScannerTask) -> ScanResult:
            return await loop.run_in_executor(None, self._run_scanner, task)

        results = await asyncio.gather(*[run_in_executor(task) for task in enabled_tasks])

        return list(results)


class ScanCache:
    """스캔 결과 캐시"""

    def __init__(self, cache_dir: str = ".security-cache"):
        self.cache_dir = cache_dir
        self._cache: dict[str, ScanResult] = {}

    def get_cache_key(self, scanner: str, workspace: str, files_hash: str) -> str:
        """캐시 키 생성"""
        import hashlib

        key = f"{scanner}:{workspace}:{files_hash}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def get(self, key: str) -> ScanResult | None:
        """캐시에서 가져오기"""
        return self._cache.get(key)

    def set(self, key: str, result: ScanResult) -> None:
        """캐시에 저장"""
        self._cache[key] = result

    def invalidate(self, key: str | None = None) -> None:
        """캐시 무효화"""
        if key:
            self._cache.pop(key, None)
        else:
            self._cache.clear()
