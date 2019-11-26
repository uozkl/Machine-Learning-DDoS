import pickle
import sys
from process.preprocess import Preprocess

# Load classifier
with open('models/clf.pkl', 'rb') as f:
    clf = pickle.load(f)
# Load file
if len(sys.argv) == 1:
    raise ValueError("Need file path")
path = sys.argv[1]
# Generate features
data = Preprocess(path)
df = data.gen_feature_df_conn()
df = [i[1:] for i in df]
# Predict
y = clf.predict_proba(df)
label = [i.index(max(i)) for i in y]
confidence = [max(i) for i in y]
# Combine result and export
df["Label"] = y
df["Confidence"] = confidence
df.to_csv("Predict.csv", mode='w', index=False)