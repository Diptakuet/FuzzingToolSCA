# DOESNT WORK

import pandas as pd
import matplotlib.pyplot as plt

class CSVGraphPlotter:
    def __init__(self, csv_path):
        self.csv_path = csv_path
        self.data = pd.read_csv(csv_path)

    def list_columns(self):
        """
        Lists the column names of the CSV file.
        """
        return self.data.columns.tolist()

    def plot_graph(self, x_column, y_column, kind='line', title='Graph', xlabel='X-axis', ylabel='Y-axis'):
        """
        Plots a graph based on the specified columns.

        :param x_column: The name of the column to be used for the x-axis.
        :param y_column: The name of the column to be used for the y-axis.
        :param kind: Type of plot (e.g., 'line', 'bar', 'scatter').
        :param title: The title of the graph.
        :param xlabel: Label for the x-axis.
        :param ylabel: Label for the y-axis.
        """
        if x_column not in self.data.columns or y_column not in self.data.columns:
            raise ValueError("Specified columns not found in the CSV file.")

        self.data.plot(x=x_column, y=y_column, kind=kind, title=title)
        plt.xlabel(xlabel)
        plt.ylabel(ylabel)
        plt.show()