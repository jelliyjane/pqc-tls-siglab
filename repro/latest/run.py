"""Run only the selected final four-cost, training-max policy."""
import argparse
from pathlib import Path
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'code'))
from rl_weight_selector.scaling_reference_ablation import run

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--split', choices=['condition', 'region'], required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    run(SimpleNamespace(reference='train-max', split=args.split,
                        input=HERE.parents[1] / 'results/latest/inputs/prepared.json.gz',
                        output_dir=args.output_dir))
