# TLS 150개 구성 및 최신 Bandit 결과

SQIsign 순수 3개·하이브리드 6개를 포함하며 HAWK 6개를 제외한 **150개 선택 후보**입니다.
기존 156개 측정 원본과 10월 3일 학습 결과는 별도 폴더에 그대로 보존합니다.

## TLS 결과

- `inputs150/algorithms.json`: 150개 구성의 정확한 식별자.
- `inputs150/tls_all50.json.gz`: 24,000개 조건, 성공 측정값 1,200,000개.
- `inputs150/tls_summary_all50.csv`: 각 조건의 50회 전체 평균·중앙값.
- 조건: 강제 X25519, 5개 지역, ICA 1–4개, BW 1/5/50/100 Mbps, 설정 손실 0/1%.
- 시간 범위는 TCP 연결 시작부터 TLS Finished 전송까지이며 TCP 수립 시간이 포함됩니다.
- RTT는 실험 메타데이터의 대표값이지 매 실행에서 측정한 RTT 평균이 아닙니다.
- 인증서 크기와 서명·검증 비용, 학습 입력은 기존
  [inputs](../bandit_sqisign_20261003/inputs/)를 공유합니다.

## 별도 보존한 학습·비교 결과

| 폴더 | 실험 |
| --- | --- |
| `bandit_cost4_loss_probability_20261008` | 4개 비용, 손실확률 입력, 체인 검증 비용 |
| `bandit_cost4_cv_verify_20261008` | CertificateVerify 검증 비용을 추가한 비교 |
| `bandit_loss_probability_20261008` | 5개 비용, 손실확률 입력 |
| `bandit_loss5_unclipped_20261008` | 5개 비용, 손실률 percentage-point 입력 |
| `log_context_ablation_20261009` | 로그 변환과 선형 스케일링 비교 |
| `scaling_reference_ablation_20261009` | 고정 기준값과 학습 데이터 최댓값 비교 |

각 평가 폴더에는 선택 기록, 분할, 설정, 결과 요약 및 `models.tar.gz`가 있습니다.
압축 파일마다 모델 JSON 75개가 들어 있습니다. 스케일링 비교의 `verified/`는
별도 검증 실행이며 상위 실행의 결과와 합쳐 집계하지 않습니다.
상위 초기 실행의 `scaling_audit.json` 4개는 불완전한 JSON으로 저장되어 있어
내용을 복구·추정하지 않고 `.incomplete.txt`로 보존했습니다. 스케일링 비교에는
완료된 `verified/` 아래의 메타데이터와 결과를 사용하세요.

이 자료는 **오프라인 측정 데이터 replay**입니다. 운영 중 온라인 학습 결과가 아닙니다.
Bandit은 조건별 50회 중 빠른 35회를 사용하며, 위 TLS CSV의 전체 50회 평균과
집계 기준이 다릅니다. 5개 seed는 독립된 네트워크 측정 5회가 아닙니다.
성능이 나빠진 비교 결과도 포함하며 특정 모델을 최종 배포 모델로 지정하지 않습니다.

재학습 명령과 코드 설명은 [재현 안내](../../repro/bandit_update_20261010/README.md)에 있습니다.
`MANIFEST.json`은 원본·배포 해시를 기록하며 `SHA256SUMS`는 배포 파일 전체를 검증합니다.
공개 자료에는 인증서 비밀키, 접속 자격증명, 호스트 접속 정보나 전체 연결 로그를 포함하지 않습니다.
