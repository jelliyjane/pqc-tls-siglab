# PQC TLS SigLab

PQC 서명 기반 TLS 실험의 결과와 알고리즘 식별자, 비용 프로파일, 빌드 자료를 모아 둔 저장소입니다.
기존 Pure PQC 49개와 Hybrid Composite 98개, 총 147개 인증서 후보의 결과를 보존하며,
SQIsign 순수·컴포짓 9개를 추가한 156개 후보 데이터와 별도 LinUCB 재평가를 제공합니다.

## 저장소 구성

| 폴더 | 들어 있는 자료 |
| --- | --- |
| [results/bandit_sqisign_20261003/](results/bandit_sqisign_20261003/README.md) | SQIsign 포함 Bandit-only 평가 결과, 학습 모델, 재현 입력과 과거 147개 후보 참고 결과 |
| [repro/bandit_sqisign_20261003/](repro/bandit_sqisign_20261003/README.md) | LinUCB 구현, 파라미터, 실행 및 모델 검증 방법 |
| [results/pc_tls_20260929/](results/pc_tls_20260929/README.md) | PC 실험 결과 CSV, 서버 서명 비용과 클라이언트 검증 비용, 실험 조건과 집계 방식 |
| [repro/pc147/](repro/pc147/README.md) | 파레토 필터 작업 안내, 147개 후보와 OpenSSL 식별자, TLS code point 매핑, 버전 기록과 추가 provider 패치 |
| [scripts/](scripts/) | OpenSSL, liboqs, oqs-provider 빌드, 실행 환경 설정, TLS 간이 테스트 스크립트 |
| [src/](src/) | TLS 테스트용 C 코드 |
| [config/](config/) | Pure PQC 49개 실험 대상 목록 |
| [patches/](patches/) | OpenSSL 핸드셰이크 시간 측정 패치 |

## 파레토 필터 작업은 여기부터

1. [작업 안내](repro/pc147/README.md)에서 구현 순서와 비용 데이터의 범위를 확인합니다.
2. [147개 후보 매핑](repro/pc147/algorithm_mapping.json)에 [서명 비용 CSV](results/pc_tls_20260929/server_sign_frankfurt_evp_v2.csv)와 [검증 비용 CSV](results/pc_tls_20260929/client_verify_seoul_evp_v2.csv)를 `algorithm` 이름으로 연결합니다.
3. [TLS 실험 결과 안내](results/pc_tls_20260929/README.md)를 보고 비교할 조건과 결과 CSV를 선택합니다.

기존 결과를 이용한 파레토 필터 분석에는 OpenSSL 재설치나 비용 재측정이 필요하지 않습니다.
클라이언트 지원 목록과 보안 정책으로 후보를 먼저 제한한 뒤, 그 안에서 파레토 필터를 적용합니다.

## 빌드 자료가 필요한 경우

버전, commit, provider 코드와 빌드 설정은 [빌드 및 재측정 안내](repro/pc147/BUILD.md)에 정리했습니다.

기존 PC release는 40,440개 조건의 요약 CSV와 147개 후보의 비용 프로파일입니다.
별도 Bandit release에는 강제 X25519의 156개 후보·24,960개 조건에 대한
1,248,000개 측정 시간 값, 비용 입력, SQIsign 포함 학습 모델과 평가 결과가 있습니다.
전체 원시 연결 로그나 인증서 비밀키는 포함하지 않습니다.
재빌드 자료만으로 당시 측정 환경이 완전히 재현된다고 보장하지는 않습니다.
