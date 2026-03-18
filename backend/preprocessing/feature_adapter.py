import pandas as pd
import numpy as np

from backend.config import get_processed_data_path


class FeatureAdapter:
    def __init__(self):
        # Load feature templates (column structures)
        self.templates = {
            "nsl_kdd": self._load_template("nsl_kdd"),
            "cicids": self._load_template("cicids")
        }

    def _load_template(self, dataset):
        """
        Load processed dataset to extract feature structure
        """
        path = get_processed_data_path(dataset)
        df = pd.read_csv(path, nrows=1)

        # Remove label column
        features = [col for col in df.columns if col != "label"]

        return features

    def align_features(self, df, dataset):
        """
        Align input data to match model feature structure
        """
        expected_features = self.templates[dataset]

        # Add missing columns
        for col in expected_features:
            if col not in df.columns:
                df[col] = 0

        # Remove extra columns
        df = df[expected_features]

        return df

    def transform(self, input_data, dataset):
        """
        Main function:
        input_data → aligned feature vector
        """

        # Convert input to DataFrame
        if isinstance(input_data, dict):
            df = pd.DataFrame([input_data])
        else:
            df = input_data.copy()

        # Clean column names (same logic as preprocessing)
        df.columns = [
            col.strip().lower()
            .replace(" ", "_")
            .replace("/", "_per_")
            .replace("-", "_")
            for col in df.columns
        ]

        # Convert to numeric
        for col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

        df = df.fillna(0)

        # Align with template
        df = self.align_features(df, dataset)

        return df


# Singleton instance (recommended)
adapter = FeatureAdapter()