#!/bin/bash
### make sure that you have modified the EXP_NAME, CKPT, DATASETS_TEST
eval "$(conda shell.bash hook)"
conda activate dire

EXP_NAME="lsun_adm"
CKPT="data/exp/lsun_adm/ckpt/model_epoch_latest.pth"
DATASETS_TEST="lsun_adm"
python test.py --ckpt $CKPT --exp_name $EXP_NAME datasets_test $DATASETS_TEST batch_size 16 num_workers 0