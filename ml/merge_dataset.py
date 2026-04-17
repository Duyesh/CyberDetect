import pandas as pd

#Load dataset
d1 = pd.read_csv("ml/dataset.csv")
d2 = pd.read_csv("ml/generated_dataset.csv")

# Combine
combined = pd.concat([d1, d2], ignore_index=True)

# Shuffle (VERY IMPORTANT)
combined = combined.sample(frac=1).reset_index(drop=True)

# Save final dataset
combined.to_csv("ml/final_dataset.csv", index=False)

print("Final dataset created!")