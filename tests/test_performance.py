"""Performance: the hunt must stay fast and memory-flat on large logs (it streams line by line)."""
import random
import time
import tracemalloc

from bluetriage.detectors import analyze

LINES = 100_000


def write_big_log(path, n=LINES):
    rng = random.Random(7)
    templates = [
        "Nov  9 03:{m:02d}:{s:02d} web01 sshd[{pid}]: Failed password for {user} from 203.0.113.{a} port {port} ssh2",
        "Nov  9 03:{m:02d}:{s:02d} web01 sshd[{pid}]: Accepted publickey for ops from 192.168.1.{a} port {port} ssh2",
        '198.51.100.{a} - - [09/Nov/2026:03:{m:02d}:{s:02d} +0000] "GET /products.php?id={pid} HTTP/1.1" 200 512 '
        '"-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0"',
        '203.0.113.{a} - - [09/Nov/2026:03:{m:02d}:{s:02d} +0000] "GET /p.php?id=1%20UNION%20SELECT%20{pid} '
        'HTTP/1.1" 500 1 "-" "sqlmap/1.8"',
        "Nov  9 03:{m:02d}:{s:02d} web01 CRON[{pid}]: pam_unix(cron:session): session opened for user root",
    ]
    with path.open("w") as handle:
        for _ in range(n):
            handle.write(rng.choice(templates).format(
                m=rng.randrange(60), s=rng.randrange(60), pid=rng.randrange(1000, 99999),
                user=rng.choice(["root", "admin", "oracle", "test"]), a=rng.randrange(1, 255),
                port=rng.randrange(1024, 65535)) + "\n")


def test_100k_lines_throughput(tmp_path):
    log = tmp_path / "big.log"
    write_big_log(log)
    started = time.perf_counter()
    result = analyze([log])
    elapsed = time.perf_counter() - started
    print(f"\n{LINES} lines / {log.stat().st_size / 1e6:.1f} MB in {elapsed:.2f}s ({LINES / elapsed:,.0f} lines/s)")
    assert result.lines_scanned == LINES
    assert elapsed < 15  # ~3s on a laptop-class CPU; generous for slow CI runners


def test_memory_does_not_grow_with_file_size(tmp_path):
    """Streaming check: 4x more lines must not mean ~4x more memory."""
    peaks = []
    for n in (10_000, 40_000):
        log = tmp_path / f"{n}.log"
        write_big_log(log, n)
        tracemalloc.start()
        analyze([log])
        peaks.append(tracemalloc.get_traced_memory()[1])
        tracemalloc.stop()
    print(f"\npeak memory: 10k lines {peaks[0] / 1e6:.2f} MB, 40k lines {peaks[1] / 1e6:.2f} MB")
    assert peaks[1] < 2 * peaks[0]
