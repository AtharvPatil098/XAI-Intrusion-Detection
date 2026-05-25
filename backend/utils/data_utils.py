import pandas as pd

def load_csv(path):
    return pd.read_csv(path)


def normalize_df(df):
    return (df - df.min()) / (df.max() - df.min())