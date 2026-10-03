"""Run the published Bandit-only replay without SSH or TLS installation."""
import argparse
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'code'))
from rl_weight_selector.sqisign_bandit_release import run

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--split',choices=('region','condition'),required=True)
    p.add_argument('--output-dir',type=Path,required=True,help='New output directory; existing outputs are never overwritten')
    a=p.parse_args()
    run(HERE.parents[1]/'results/bandit_sqisign_20261003/inputs/prepared.json.gz',a.output_dir,a.split)
