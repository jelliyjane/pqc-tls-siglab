# 최종 실험 결과

## TLS: 150개 구성

- SQIsign 순수 3개와 하이브리드 6개 포함, HAWK 6개 제외.
- `inputs/algorithms.json`: 전체 150개 식별자.
- `inputs/tls_all50.json.gz`: 24,000개 조건, 성공 측정 1,200,000개.
- `inputs/tls_summary_all50.csv`: 조건별 50회 전체 평균·중앙값.
- 강제 X25519, 지역 5개, ICA 1–4개, BW 1/5/50/100 Mbps, 설정 손실 0/1%.
- 측정 구간: TCP 연결 시작부터 TLS Finished 전송까지. RTT는 실험의 대표 메타데이터.
- 서명·검증 프로파일과 인증서 크기: `inputs/*costs.csv`, `server_sign.csv`, `seoul_client_verify.csv`.

## 최종 Bandit 설정

Disjoint LinUCB, 4개 비용(서명·전송·추가 왕복·체인 검증 추정),
286개 가중치 arm, context `[1, log-scaled RTT, log-scaled BW, interaction, loss probability]`.
RTT/BW는 `log1p(value)/log1p(training maximum)`으로 변환합니다.
내부 validation에는 내부 training, test에는 외부 training의 최댓값만 사용합니다.
체인 검증 비용에는 별도의 CertificateVerify 검증 한 번을 추가하지 않습니다.

- `region/`: 지역 holdout, 모델 75개와 test 결정 7,200개.
- `condition/`: 조건 조합 holdout, 모델 75개와 test 결정 7,200개.
- 각 `models.tar.gz`: 학습된 모델 JSON. 설정, alpha, 가중치, 정규화 범위와 학습 상태 포함.
- 각 `metrics.json`, `test_decisions.json`: 평가 요약과 개별 선택 기록.
- 각 `split_manifest.json`, `validation_search.json`, `scaling_audit.json`: 분할·선택·스케일링 기록.
- `inputs/prepared.json.gz`: 원래 학습 입력을 바이트 단위로 보존한 파일. 이미 150개 선택 후보로 필터링되어 있습니다.

원측정 50회 전체 통계와 달리 Bandit은 조건별 빠른 35회/50회를 사용합니다.
오프라인 replay이며 테스트 중 갱신하지 않습니다. 5개 seed는 별도 네트워크 측정이 아닙니다.
Condition holdout은 개발 과정의 평가이며 독립적인 최종 외부 테스트로 주장하지 않습니다.
체인 검증 시간은 단일 검증 프로파일에 인증서 수를 곱한 추정값입니다.
입력 파일·모델 메타데이터의 156개 원측정 후보 언급은 과거 원자료의 출처이며,
이 배포의 실제 TLS 및 선택 후보는 150개입니다.

`PROVENANCE.json`의 과거 경로는 출처 기록입니다. 이전 커밋에서 복구할 수 있으며
현재 실행에는 이전 폴더가 필요하지 않습니다.
[실행·검증 방법](../../repro/latest/README.md).
