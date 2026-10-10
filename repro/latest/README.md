# 최종 모델 재현

Python 3.12 이상과 NumPy가 필요합니다. 배포 검증은 NumPy 2.3.5에서 수행했습니다.
저장소 루트에서 실행합니다. 네트워크·서버 접속·인증서 비밀키가 필요하지 않습니다.

```bash
python repro/latest/check_release.py
python repro/latest/run.py --split condition --output-dir outputs/final-condition
python repro/latest/run.py --split region --output-dir outputs/final-region
```

`run.py`는 최종 설정(4개 비용, chain-only 검증 추정, 로그 변환,
손실확률, training-max 스케일링)으로만 실행합니다. 새 출력 경로를 사용해야 합니다.
입력·모델의 출처와 학습 프로토콜은 [결과 안내](../../results/latest/README.md)에 있습니다.

`code/`에는 최종 실행에 필요한 의존 코드가 보존되어 있습니다. 내부 모듈에 남은
과거 옵션과 상수는 다른 실험 결과를 배포한다는 의미가 아닙니다.
현재 코드 스냅샷과 당시 기록된 소스 해시는 `PROVENANCE.json`에 구분되어 있습니다.
