
#curl -L -o ./data/network-intrusion-dataset.zip https://www.kaggle.com/api/v1/datasets/download/chethuhn/network-intrusion-dataset

import kagglehub
import os

os.makedirs("data", exist_ok=True)
path = kagglehub.dataset_download("chethuhn/network-intrusion-dataset",
                                  output_dir="data",)

print("Path to dataset files:", path)