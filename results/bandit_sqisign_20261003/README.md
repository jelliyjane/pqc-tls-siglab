# Bandit-only: SQIsign 포함 재평가

2026-10-03에 SQIsign 순수·컴포짓 9개 후보를 추가해 기존 **5항 비용 LinUCB**를
별도 모델로 학습·평가했습니다. 기존 모델과 원측정값은 수정하지 않았습니다.
이 결과는 저장된 TLS 측정값으로 수행한 offline replay이며 새 온라인 TLS
Bandit 실험이 아닙니다. Pareto 필터는 사용하지 않습니다.

코드·학습 파라미터·실행 명령은 [재현 안내](../../repro/bandit_sqisign_20261003/README.md)에 있습니다.

## 결과

| 평가 | 기존 147개 측정 후보 기준 RL 평균 | SQIsign 포함 RL 평균 | 같은 후보 집합의 oracle 평균 | SQIsign 선택 / 전체 결정 |
| --- | ---: | ---: | ---: | ---: |
| 미관측 지역 holdout | 296.213803 ms | 326.092773 ms | 282.142099 ms | 282 / 7,200 |
| 조건 조합 holdout | 293.367662 ms | 293.099185 ms | 282.142099 ms | 22 / 7,200 |

SQIsign 추가가 모든 평가에서 개선을 의미하지 않습니다. 지역 holdout에서는
평균 지연이 증가했고, 조건 조합 holdout에서는 거의 같았습니다. 성능에 맞춰
평가 프로토콜이나 alpha 후보를 변경하지 않았습니다. SQIsign은 실제 후보
집합에 포함되었고 선택 기록에도 나타납니다. **모든 SQIsign 파라미터가 최적이거나
선택되었다는 뜻은 아닙니다.**

각 평균은 1,440개 선택 상황 × seed 5개의 7,200개 결정에 대한 산술 평균입니다.
각 상황의 알고리즘별 TLS 값은 조건당 50회 중 빠른 35회의 평균입니다.
원측정 캠페인의 all-50 평균과 구분해야 합니다. 이 표는 유의성 검정 결과가
아니며 seed를 독립된 네트워크 실험으로 취급하지 않습니다.

## 범위

- 측정: 156개 후보 = 기존 147개 + SQIsign 순수 3개 및 컴포짓 6개.
- 조건: 강제 X25519, 1–4 ICA, 5개 지역, BW 1/5/50/100 Mbps, loss 0/1%.
- 총 24,960개 알고리즘·환경 조건, 1,248,000개 성공 측정 시간 값.
- 학습 정책: 기존 HAWK 6개 제외 규칙 유지. 실제 선택 후보는 150개입니다.
- 순수 SQIsign: `sqisign1`, `sqisign3`, `sqisign5`.
- 컴포짓: `p256_sqisign1`, `rsa3072_sqisign1`, `p384_sqisign3`,
  `rsa7680_sqisign3`, `p521_sqisign5`, `rsa15360_sqisign5`.
- SQIsign은 nist-v3 reference 구현, commit
  `6d017708db403bf83977fa70770fc4f7f9e9ff21`입니다.

## 파일 안내

| 경로 | 내용 |
| --- | --- |
| `region/` | 기존과 같은 5-fold whole-region holdout 결과 |
| `condition/` | 기존과 같은 5-fold grouped-condition holdout 결과 |
| 각 `models.tar.gz` | fold × L1/L3/L5 × seed의 모델 75개(JSON) |
| 각 `metrics.json` | 파라미터와 전체 평가 요약, 제한사항 |
| 각 `test_decisions.csv` | 7,200개 상황별 선택 알고리즘, 가중치, TLS, oracle, regret |
| 각 `validation_search.csv` | 내부 validation의 alpha × seed 결과 |
| 각 `fold_summary.csv`, `split_manifest.json` | 선택된 alpha와 분할 기록 |
| `prior147_reference/` | 기존 지역 holdout 결과·모델 75개와 기존 조건 holdout 요약; 새 결과와 섞지 않음 |
| `inputs/prepared.json.gz` | 학습 진입점에 필요한 context·후보 비용·빠른 35개 TLS 값 |
| `inputs/tls_all50.json.gz` | 156개 후보의 24,960개 조건별 원측정 시간 50개 및 run ID |
| `inputs/server_sign.csv`, `inputs/seoul_client_verify.csv` | 156개 후보의 역할별 EVP 평균; 아래 지정 열 사용 |
| `inputs/pure_costs.csv`, `inputs/composite_costs.csv` | 실제 인증서 체인 크기·제시 인증서 수와 연결한 비용 입력 |
| `inputs/sqisign_cost_raw/` | SQIsign의 역할별 EVP 원측정 50회, 기존 측정 재사용분 포함 |
| `inputs/provenance.json`, `SHA256SUMS` | 원자료 및 배포 파일 해시, 후보 정책 |

학습 모델은 압축을 풀면 `models/*.json`으로 읽을 수 있습니다. `a_inverse`, `b`,
`counts`, `alpha`, action 가중치, 정규화 범위, 학습·테스트 context가 저장되어 있습니다.
모델 JSON 자체에 TLS 원측정 전체나 인증서 비밀키는 들어 있지 않습니다.

## 비용 입력의 출처

기존 147개 EVP 프로파일을 그대로 재사용했습니다. SQIsign은 실제 1ICA TLS
leaf 키를 사용하며, 기존에 측정된 Frankfurt 순수 3개 비용도 재사용했습니다.
누락된 Frankfurt 컴포짓 6개와 Seoul client1의 9개 비용만 새로 측정했습니다.
모두 OpenSSL 3.5.7의 EVP 경로, 준비 5회·본 측정 50회·1,000ms 간격입니다.
provider 빌드 해시와 각 키의 SHA256은 provenance에 구분되어 있습니다.

- `server_sign.csv`의 `sign_mean_ms`를 서명 비용으로 사용합니다.
- `seoul_client_verify.csv`의 `verify_mean_ms`를 검증 비용으로 사용합니다.
- 두 파일에 있는 반대 역할의 열을 서로 바꿔 쓰지 않습니다.
- `signature_bytes_mean`은 서명 크기이지 인증서 체인 크기가 아닙니다.
- 검증은 CertificateVerify 한 번의 비용이며, 전체 체인 검증 비용은
  인증서 수를 곱한 proxy입니다. 실제 체인 검증 시간이라고 표시하지 않습니다.
- 같은 역할의 호스트를 사용했어도 측정 시점과 CPU 상태가 다를 수 있습니다.
  특히 burstable AWS 인스턴스이므로 하드웨어 이름만으로 동일 비용을 보장하지 않습니다.

TLS 시간에는 기존 `tcp_connect_start_to_tls_finished_openssl_internal` 방식의
TCP 연결 수립 시간이 포함됩니다. 실행 실패·재시도 journal과 성공 원자료를
중복 합산하지 않았습니다. 기본 KEX 및 Top1M 스캔 결과는 이 데이터에 포함하지 않습니다.

## 재현·검증

```bash
python repro/bandit_sqisign_20261003/check_release.py
```

검증기는 모든 배포 파일의 해시를 확인하고, all-50에서 빠른 35개를 다시
선택해 학습 입력과 비교합니다. 이어 새 모델 150개를 압축본에서 읽어
14,400개 테스트 결정의 action·알고리즘·TLS·oracle을 다시 계산합니다.
재학습하려면 [실행 안내](../../repro/bandit_sqisign_20261003/README.md)를 사용하세요.

공개 자료는 측정값과 모델을 재현하기 위한 것입니다. AWS 접속 정보, 비밀키,
전체 연결 로그나 당시 provider 설치 디렉터리를 제공하는 자료가 아닙니다.
