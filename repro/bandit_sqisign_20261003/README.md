# SQIsign 포함 Bandit-only / LinUCB 자료

이 폴더는 기존 5항 LinUCB 실험에 SQIsign 순수·컴포짓 9개 후보를 추가한
**오프라인 측정 데이터 replay**의 구현입니다. 실제 서버에서 새 온라인
Bandit 실험을 수행했다는 뜻은 아닙니다. SQLite 구현도 아닙니다.

## 무엇을 학습하나요?

LinUCB의 action은 서명 알고리즘 이름이 아니라 **5개 비용의 가중치 벡터**입니다.
주어진 RTT·대역폭에서 가중치를 고른 뒤, 가중합 비용이 가장 작은 후보를
선택합니다. 선택한 후보의 TLS 시간 하나만 보상으로 받아 해당 action을
갱신합니다. Pareto 필터는 적용하지 않습니다.

비용 항목은 서명 시간, 전송 시간, 추가 왕복 지연, 검증 비용, 이진 tail
표시입니다. 앞의 네 항목은 학습 부분에서 얻은 min/max로 정규화하고,
tail은 0/1 그대로 사용합니다. 검증 비용은 단일 EVP 검증 비용에 인증서 수를
곱한 **추정값**이지 체인 전체 검증 실측값은 아닙니다.

| 설정 | 값 |
| --- | --- |
| 알고리즘 | Disjoint LinUCB, ridge 1 |
| 입력 | bias, log RTT, log bandwidth, 두 값의 곱 |
| action | 0 이상이고 합이 1인 5차원 가중치, 간격 0.1, 총 1,001개 |
| alpha 후보 | 0.01, 0.05, 0.1, 0.25; 내부 validation으로 선택 |
| seed | 42, 43, 44, 45, 46 |
| 보상 | 선택한 후보의 `-TLS_ms / 1000` |
| 업데이트 | 선택한 action 하나만 업데이트 |
| 테스트 | 동결 UCB 정책, 테스트 중 업데이트 없음 |
| 집계 | 각 조건 50개 원측정 중 빠른 35개; 유지된 run 순서를 보존 |
| 정책 | 기존 HAWK 6개 제외 정책 유지, 156개 측정 후보 중 150개 선택 가능 |

입력 RTT는 측정 파일에 저장된 대표 RTT입니다. loss·ICA는 정책의 독립 입력이
아니며 후보 비용 또는 관찰 결과에만 반영됩니다. ML-DSA-44를 L1 비교군에
묶는 기존 규칙은 원 알고리즘의 보안 범주 2를 범주 1로 바꾸는 것이 아닙니다.

## 코드와 결과 위치

- `code/rl_weight_selector/partial_feedback_linucb.py`: LinUCB 점수·업데이트·저장 형식.
- `code/rl_weight_selector/tail5_region_holdout.py`: 5항 비용, 정규화, 가중치별 선택, 학습.
- `code/rl_weight_selector/sqisign_bandit_release.py`: 재현용 진입점과 두 holdout 방식.
- [결과·학습 모델·입력 자료](../../results/bandit_sqisign_20261003/README.md).
- `SOURCE_PROVENANCE.json`: 가져온 원본 코드의 해시와 이식 변경 기록.

`code/`의 과거 모듈은 기존 구현의 의존성을 보존하기 위해 포함했습니다.
과거 모듈의 기본 경로로 직접 실행하지 말고 아래 `run.py`를 사용하세요.
예전 3항 구현도 의존 코드에 남아 있지만 이 release의 학습 경로는 5항입니다.

## 실행

저장소 루트에서 Python 3.13 환경을 사용합니다. 측정에 쓰인 OpenSSL이나
provider를 설치할 필요는 없습니다. 네트워크 연결·AWS 계정·인증서 비밀키도
필요하지 않습니다.

```bash
python3.13 -m venv .venv-bandit
.venv-bandit/bin/python -m pip install -r repro/bandit_sqisign_20261003/requirements.txt
.venv-bandit/bin/python repro/bandit_sqisign_20261003/check_release.py
.venv-bandit/bin/python repro/bandit_sqisign_20261003/run.py --split region --output-dir outputs/replay-sqisign-region
.venv-bandit/bin/python repro/bandit_sqisign_20261003/run.py --split condition --output-dir outputs/replay-sqisign-condition
```

출력 폴더가 이미 있으면 중단합니다. 새 경로를 지정하면 기존 결과를 보존한
채 다시 실행할 수 있습니다. 각 평가에서 모델 75개, test decision 7,200개,
validation 검색 결과와 fold별 alpha가 생성됩니다.

## 두 평가의 차이

- **Region holdout:** 5개 지역 중 1개 전체를 test로 둡니다. 나머지 중 3개로
  tuning하고 1개로 alpha를 정한 뒤, 4개 전체로 fit합니다. 지역별로 반복합니다.
- **Condition holdout:** `(지역, ICA, loss, bandwidth)` 160개 조합을 고정 seed
  20260927로 5-fold 분할합니다. fold마다 128개 fit, 32개 test이며 한 조합의
  모든 후보와 반복 측정은 함께 이동합니다. 내부 validation 분리 seed도 기존과 같습니다.

원자료의 과거 30/10/10 temporal split을 이 두 평가와 혼동하지 마세요.
이 release는 기존 5항 실험과 같은 whole-region/grouped-condition 프로토콜입니다.
Condition holdout은 개발 과정에서 설계된 평가이며 독립된 최종 검증셋이라고
주장하지 않습니다. seed 5개는 새로운 네트워크 실험 5회가 아닙니다.
