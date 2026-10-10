# PQC TLS SigLab

SQIsign을 포함하고 HAWK를 제외한 **150개 서명 구성**의 TLS 측정 자료와 최종 Bandit 평가입니다.
이전 실험과 중간 비교 결과는 현재 파일 목록에서 제거했습니다.

| 경로 | 내용 |
| --- | --- |
| [results/latest](results/latest/README.md) | TLS 측정값 120만 개, 비용 프로파일, 지역·조건 holdout 결과와 모델 |
| [repro/latest](repro/latest/README.md) | 최종 설정의 실행 코드와 검증 방법 |
| `scripts/`, `src/`, `patches/`, `config/` | 기존 TLS 측정·빌드 보조 자료; 전체 150개 구성 목록은 `results/latest/inputs/algorithms.json` 참조 |

최종 설정은 4개 비용 항, chain-only 검증 비용 추정, 손실확률 입력,
로그 변환 및 학습 데이터 최댓값 스케일링입니다. Pareto 필터는 사용하지 않습니다.
결과는 오프라인 측정 데이터 replay이며 실제 서비스의 온라인 학습 결과가 아닙니다.

TLS 통계는 **50회 전체 평균**이고 Bandit 학습·평가는 **빠른 35회/50회**를 사용합니다.
두 집계를 혼용하지 마세요. 원자료, 모델, 설정과 재현 절차는 위 두 폴더에서 확인할 수 있습니다.
