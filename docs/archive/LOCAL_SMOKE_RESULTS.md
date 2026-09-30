# 과거 로컬 간이 테스트 결과

이 자료는 초기 개발 환경에서 얻은 단발성 측정 기록입니다. 현재 PC 캠페인 결과나 파레토 필터의 비용 프로파일로 사용하지 않습니다.
최신 자료는 [PC 실험 결과](../../results/pc_tls_20260929/README.md)를 참고합니다.


These were one-shot localhost measurements on the original development machine.
Use them only as sanity checks, not final benchmark data.

| Algorithm | Certificate DER | TLS handshake |
|---|---:|---:|
| Falcon512 | 1,788B | 10ms |
| HAWK512 | 1,819B | 30ms |
| ML-DSA44 | 3,981B | 10ms |
| FAEST128s | 4,773B | 110ms |
| FAEST128f | 6,191B | 70ms |
| SLH-DSA-SHA2-128s | 8,130B | 260ms |
| SLH-DSA-SHA2-128f | 17,362B | 30ms |
| QR-UOV level1 | 21,212B | 50ms |
| ML-DSA65 | 5,510B | 10ms |
| FAEST192s | 11,544B | 310ms |
| FAEST192f | 15,232B | 150ms |
| SLH-DSA-SHA2-192s | 16,515B | 440ms |
| SLH-DSA-SHA2-192f | 35,955B | 30ms |
| QR-UOV level3 | 55,878B | 80ms |
| Falcon1024 | 3,304B | 10ms |
| HAWK1024 | 3,901B | 30ms |
| ML-DSA87 | 7,468B | 10ms |
| FAEST256s | 20,980B | 490ms |
| FAEST256f | 26,832B | 230ms |
| SLH-DSA-SHA2-256s | 30,099B | 400ms |
| SLH-DSA-SHA2-256f | 50,163B | 60ms |
| QR-UOV level5 | 136,313B | 90ms with large-cert client |
