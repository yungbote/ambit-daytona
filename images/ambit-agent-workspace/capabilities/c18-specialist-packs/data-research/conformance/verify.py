from __future__ import annotations

import argparse
import importlib.metadata
import json
import math
import sys
from pathlib import Path

import duckdb
import matplotlib
import networkx as nx
import numpy as np
import pandas as pd
import polars as pl
import pyarrow as pa
import pyarrow.ipc as ipc
import pyarrow.parquet as pq
import scipy
import sympy
from matplotlib import pyplot as plt
from scipy import stats

from common import canonical_json, file_receipts, runtime_guard, sha256


PACK_REF = "ambit.runtime-pack/data-research@1"
SEED = 20260823


def _versions() -> dict[str, str]:
    names = (
        "duckdb",
        "ipykernel",
        "jupyterlab",
        "matplotlib",
        "networkx",
        "numpy",
        "pandas",
        "polars",
        "pyarrow",
        "scipy",
        "sympy",
    )
    return {name: importlib.metadata.version(name) for name in names}


def generate(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    rng = np.random.default_rng(SEED)
    frame = pd.DataFrame(
        {
            "region": ["North", "South", "West", "East"],
            "q1": [120, 90, 80, 105],
            "q2": [130, 110, 95, 115],
            "sample": np.round(rng.normal(0, 1, 4), 8),
        }
    )
    frame["total"] = frame["q1"] + frame["q2"]
    frame.to_csv(output / "revenue.csv", index=False, lineterminator="\n", float_format="%.8f")
    canonical_json(output / "revenue.json", frame.to_dict(orient="records"))
    table = pa.Table.from_pandas(frame, preserve_index=False)
    pq.write_table(
        table,
        output / "revenue.parquet",
        compression="NONE",
        use_dictionary=False,
        write_statistics=True,
        data_page_version="1.0",
    )
    with ipc.new_file(output / "revenue.arrow", table.schema) as writer:
        writer.write_table(table)

    query = duckdb.sql(
        "SELECT region, total FROM frame ORDER BY total DESC, region",
    ).df()
    assert query.iloc[0].to_dict() == {"region": "North", "total": 250}
    lazy = pl.from_pandas(frame).lazy().select(pl.col("total").sum()).collect()
    assert lazy.item() == 845
    slope = stats.linregress(frame["q1"], frame["q2"])
    assert math.isclose(slope.slope, 0.8027210884353742, rel_tol=1e-12)
    x = sympy.Symbol("x")
    assert sympy.solve(sympy.Eq(2 * x + 4, 18), x) == [7]
    graph = nx.Graph()
    graph.add_edges_from((("North", "South"), ("South", "West"), ("West", "North")))
    centrality = nx.pagerank(graph)
    assert all(math.isclose(value, 1 / 3, rel_tol=1e-12) for value in centrality.values())

    matplotlib.use("Agg")
    matplotlib.rcParams.update(
        {
            "font.family": "Noto Sans",
            "font.size": 10,
            "figure.dpi": 100,
            "savefig.dpi": 100,
            "svg.hashsalt": "ambit-c18-data-research",
        }
    )
    figure, axis = plt.subplots(figsize=(6.4, 3.6), layout="constrained")
    axis.bar(frame["region"], frame["total"], color="#1f4e78")
    axis.set_title("Revenue by region")
    axis.set_xlabel("Region")
    axis.set_ylabel("Total")
    axis.grid(axis="y", alpha=0.25)
    figure.savefig(
        output / "revenue.png",
        metadata={"Software": "Ambit C18 data-research conformance"},
    )
    plt.close(figure)

    notebook = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": ["# Reproducible revenue analysis\n"],
            },
            {
                "cell_type": "code",
                "execution_count": 1,
                "metadata": {},
                "outputs": [
                    {
                        "name": "stdout",
                        "output_type": "stream",
                        "text": ["845\n"],
                    }
                ],
                "source": ["print(120 + 130 + 90 + 110 + 80 + 95 + 105 + 115)\n"],
            },
        ],
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3.14.7",
                "language": "python",
                "name": "python3",
            },
            "language_info": {"name": "python", "version": "3.14.7"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    canonical_json(output / "analysis.ipynb", notebook)
    (output / "research.md").write_text(
        "# Reproducible revenue analysis\n\n"
        "The exact seeded environment produced a total of **845**.\n\n"
        "| Region | Total |\n|---|---:|\n| North | 250 |\n| South | 200 |\n"
        "| West | 175 |\n| East | 220 |\n",
        encoding="utf-8",
    )
    (output / "lineage.dot").write_text(
        "digraph lineage {\n  input -> query;\n  query -> chart;\n  query -> report;\n}\n",
        encoding="utf-8",
    )
    canonical_json(
        output / "environment.json",
        {
            "schema": "ambit.c18-data-environment/v1",
            "packRef": PACK_REF,
            "python": sys.version.split()[0],
            "seed": SEED,
            "timezone": "UTC",
            "versions": _versions(),
        },
    )
    canonical_json(
        output / "fixture-manifest.json",
        {
            "schema": "ambit.c18-data-fixture-manifest/v1",
            "packRef": PACK_REF,
            "rowCount": len(frame),
            "total": int(frame["total"].sum()),
            "schemaFields": [field.name for field in table.schema],
            "files": file_receipts(output),
        },
    )


def finalize(output: Path) -> None:
    first = output / "run-a"
    second = output / "run-b"
    first_files = {item["path"]: item["sha256"] for item in file_receipts(first)}
    second_files = {item["path"]: item["sha256"] for item in file_receipts(second)}
    assert first_files == second_files
    native_a = output / "native-a"
    native_b = output / "native-b"
    native_a_files = {item["path"]: item["sha256"] for item in file_receipts(native_a)}
    native_b_files = {item["path"]: item["sha256"] for item in file_receipts(native_b)}
    assert native_a_files == native_b_files
    assert (native_a / "sqlite-total.txt").read_text().strip() == "845"
    assert "Reproducible revenue analysis" in (native_a / "research.html").read_text()
    assert "<svg" in (native_a / "lineage.svg").read_text()
    with ipc.open_file(first / "revenue.arrow") as reader:
        assert reader.read_all().num_rows == 4
    assert pq.read_table(first / "revenue.parquet").num_rows == 4
    guard = runtime_guard(output / "runtime-guard.tsv")
    assert guard["pack"] == "data-research"
    pack = json.loads((Path(__file__).resolve().parents[1] / "pack.lock.json").read_text())
    required = pack["conformance"]["requiredChecks"]
    canonical_json(
        output / "conformance-receipt.json",
        {
            "schema": "ambit.runtime-pack-conformance/v3",
            "packRef": PACK_REF,
            "outcome": "passed",
            "fullImage": True,
            "network": "none",
            "runtime": guard,
            "checks": [{"ref": check, "outcome": "passed"} for check in required],
            "reproduction": {
                "seed": SEED,
                "runA": sha256(first / "fixture-manifest.json"),
                "runB": sha256(second / "fixture-manifest.json"),
                "byteEquivalent": True,
            },
            "files": file_receipts(output),
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("generate", "finalize"))
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "generate":
            generate(args.output)
        else:
            finalize(args.output)
    except (AssertionError, OSError, ValueError) as error:
        print(f"data-research-conformance: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
