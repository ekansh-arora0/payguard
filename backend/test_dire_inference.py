import sys

import torch
import torch.nn as nn
import torchvision.transforms as transforms
from PIL import Image

sys.path.append("/app/DIRE")
from utils.utils import get_network


def test_inference():
    print("Initializing model...")
    model = get_network("resnet50")
    print("Loading state dict...")
    sd = torch.load(
        "/app/DIRE/data/exp/lsun_adm/ckpt/model_epoch_latest.pth", map_location="cpu"
    )
    sd = sd["model"] if "model" in sd else sd
    model.load_state_dict(sd)
    model.eval()

    print("Creating dummy input...")
    x = torch.randn(1, 3, 224, 224)

    print("Running inference...")
    try:
        with torch.no_grad():
            y = model(x)
        print("Inference Success:", y.shape)
        print("Result prob:", y.sigmoid().item())
    except Exception as e:
        print("Inference Failed with exception:", e)


if __name__ == "__main__":
    test_inference()
