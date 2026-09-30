# 파레토 필터 실험 안내

기존 PC 실험 결과를 사용해, 클라이언트가 지원하는 후보 중 비용 면에서 지배되는 후보를 제거하는 파레토 필터를 구현하기 위한 자료입니다. 기존 결과로 분석할 때는 OpenSSL을 다시 빌드하거나 비용을 재측정할 필요가 없습니다.

## 먼저 볼 파일

| 파일 | 사용할 내용 |
| --- | --- |
| [algorithm_mapping.json](algorithm_mapping.json) | Pure PQC 49개, Composite 98개의 후보 목록, 보안 정책 그룹, OpenSSL 식별자, TLS code point |
| [서버 서명 비용 CSV](../../results/pc_tls_20260929/server_sign_frankfurt_evp_v2.csv) | `algorithm`, `sign_mean_ms` |
| [클라이언트 검증 비용 CSV](../../results/pc_tls_20260929/client_verify_seoul_evp_v2.csv) | `algorithm`, `verify_mean_ms` |
| [PC 결과 README](../../results/pc_tls_20260929/README.md) | 조건별 TLS 성능 CSV, 실험 조건과 집계 방식 |

모든 파일은 대소문자를 포함한 `algorithm` 문자열로 연결합니다. 행 번호를 알고리즘 ID로 사용하지 않습니다. 시간 단위는 ms입니다.

## 작업 순서

1. 후보 목록에 서명 비용과 검증 비용을 연결합니다.
2. 클라이언트 지원 목록과 보안 정책을 적용해 비교할 후보를 정합니다.
3. 비교 지표를 정한 뒤, 모든 지표에서 다른 후보보다 같거나 나쁘고 적어도 한 지표에서 더 나쁜 후보를 제거합니다. 모든 지표가 같은 후보는 이 규칙만으로 제거하지 않습니다.
4. 클라이언트 지원 목록별로 필터 적용 전후 후보 수와 남은 알고리즘 목록을 기록합니다.
5. TLS 결과와 비교할 때는 같은 캠페인, 지역, 대역폭, 손실률, 인증서 체인 구성 안에서 비교합니다.

전체 후보에서 구한 파레토 집합을 단순히 클라이언트 지원 목록과 교집합해서는 안 됩니다. 어떤 후보를 지배하던 알고리즘이 클라이언트에서 지원되지 않을 수 있으므로, **지원 목록과 정책으로 후보를 먼저 제한한 뒤** 파레토 집합을 구합니다.

## 비용 데이터에서 주의할 점

- 서명 비용은 Frankfurt 서버, 검증 비용은 Seoul PC 클라이언트에서 측정한 기존 값입니다. 서로 다른 장비의 비용을 새로 섞지 않습니다.
- 검증 비용은 CertificateVerify 서명 한 번의 검증 비용이며, 인증서 체인 전체 검증 실측값이 아닙니다.
- `signature_bytes_mean`은 서명 크기입니다. 인증서 크기나 체인 전체 전송 크기가 아닙니다.
- **인증서 또는 체인 전송 크기를 비교 지표로 쓰려면 해당 크기 프로파일을 추가로 받아야 합니다.** 현재 공개된 비용 CSV만으로 그 지표를 구성하지 않습니다.
- X25519 캠페인은 50회 전체 평균, 기본 ClientHello 캠페인은 빠른 70%의 평균입니다. 두 집계 방식을 동일한 통계로 취급하지 않습니다.

## 식별자에서 주의할 점

- `openssl_algorithm_argument`는 실험에서 사용한 이름, `evp_signature_name`은 실행 환경에서 확인한 EVP 이름입니다. 예를 들어 `mldsa44`는 `default` provider의 `ML-DSA-44`로 연결됩니다.
- `source_security_level`은 원본 분류이며, `policy_level`은 기존 실험의 비교 그룹입니다. ML-DSA-44와 그 Composite를 L1 그룹에 묶은 것은 정책상 분류이지 알고리즘의 보안 범주를 바꾼 것이 아닙니다.
- `standard` 빌드는 Pure 49개와 기존 Composite 86개, `shake98` 빌드는 추가 Composite SLH-DSA-SHAKE 12개에 사용했습니다.
- 두 빌드 사이에서 code point 9개가 서로 다른 알고리즘에 재사용됩니다. **`(provider_build, tls_code_point_decimal)`을 함께 사용**하고, 실제 연결에서는 클라이언트와 서버의 provider 빌드를 맞춥니다. code point만으로 알고리즘을 식별하지 않습니다.

## 검증 및 재측정이 필요한 경우

자료의 후보 수, 비용 CSV 연결, 해시를 확인하려면 저장소 루트에서 실행합니다.

```bash
python3 repro/pc147/check_handoff.py
```

버전, commit, 추가 provider 코드, 빌드 설정이 필요한 경우에만 [빌드 및 재측정 안내](BUILD.md)를 참고합니다. 당시 liboqs 바이너리의 정확한 소스 commit은 복원되지 않았으므로, 제공한 재빌드용 commit을 당시 commit과 동일하다고 간주하지 않습니다.
