#!/usr/bin/env python3
"""Isolated, deterministic Tesseract process/thread benchmark; no provider calls.

Run in a disposable container with an explicit CPU/memory quota. The first
invocation is labelled separately; this does not claim to evict OS caches.
"""

import argparse
import concurrent.futures
import csv
import hashlib
import json
import os
from pathlib import Path
import random
import re
import signal
import subprocess
import threading
import time
from collections import Counter

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"


def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def tokens(text):
    return re.findall(r"[a-z0-9]+", text.lower())


def quality(expected, actual):
    want, got = Counter(tokens(expected)), Counter(tokens(actual))
    common = sum((want & got).values())
    return {
        "expected_tokens": sum(want.values()),
        "actual_tokens": sum(got.values()),
        "token_recall": common / max(1, sum(want.values())),
        "token_precision": common / max(1, sum(got.values())),
        "text_sha256": hashlib.sha256(actual.encode()).hexdigest(),
        "normalized_text_sha256": hashlib.sha256(" ".join(tokens(actual)).encode()).hexdigest(),
    }


def generate():
    target = ROOT / "fixtures"
    target.mkdir(exist_ok=True)
    manifest = []
    started = time.perf_counter()
    for kind in ("text", "table", "drawing"):
        page = Image.new("RGB", (2400, 3300), "white")
        draw = ImageDraw.Draw(page)
        ground_truth = []

        def label(x, y, value, size=26, mono=False):
            draw.text((x, y), value, font=ImageFont.truetype(MONO if mono else FONT, size), fill="black")
            ground_truth.append(value)

        label(100, 70, f"SYNTHETIC {kind.upper()} REVIEW 2026", 46)
        label(100, 138, "Public benchmark fixture. Invented values. No customer information.", 26)
        if kind == "text":
            for i in range(47):
                y = 235 + i * 60
                label(110, y, f"Item {i + 1:02d}: inspect concrete footing F{i + 1:02d}, steel beam B{i + 1:02d}, and wall assembly W{i + 1:02d}.", 26)
                label(110, y + 29, f"Quantity {17 + i} units. Width {12 + i} inches. Elevation {100 + i}.25 feet. Reference drawing S{i + 1:03d}.", 23)
        elif kind == "table":
            columns = [90, 285, 1070, 1430, 1800, 2300]
            top, row_h = 250, 61
            for x in columns:
                draw.line((x, top, x, top + 45 * row_h), fill="#555555", width=2)
            for r in range(46):
                draw.line((columns[0], top + r * row_h, columns[-1], top + r * row_h), fill="#555555", width=2)
            for col, value in enumerate(("ITEM", "DESCRIPTION", "QUANTITY", "UNIT", "AMOUNT")):
                label(columns[col] + 15, top + 15, value, 27)
            materials = ["Reinforced concrete", "Structural steel beam", "Masonry block wall", "Roof insulation", "Exterior glazing"]
            for i in range(44):
                values = [f"A{i + 1:03d}", materials[i % len(materials)], str(12 + i * 7), ["CY", "LB", "SF", "SF", "EA"][i % 5], f"{1250 + i * 137}.00"]
                for col, value in enumerate(values):
                    label(columns[col] + 15, top + (i + 1) * row_h + 17, value, 25, mono=col != 1)
        else:
            # Repeatable plan-like geometry, dimensions and small annotations.
            for row in range(4):
                for col in range(3):
                    x, y = 160 + col * 735, 315 + row * 680
                    draw.rectangle((x, y, x + 560, y + 420), outline="black", width=7)
                    draw.rectangle((x + 14, y + 14, x + 546, y + 406), outline="black", width=2)
                    draw.line((x + 220, y + 14, x + 220, y + 290), fill="black", width=5)
                    draw.line((x + 220, y + 290, x + 546, y + 290), fill="black", width=5)
                    for dx in (35, 495):
                        for dy in (35, 355):
                            draw.rectangle((x + dx, y + dy, x + dx + 25, y + dy + 25), outline="black", width=3)
                    draw.line((x, y - 50, x + 560, y - 50), fill="black", width=2)
                    draw.line((x - 50, y, x - 50, y + 420), fill="black", width=2)
                    for px in (x, x + 560):
                        draw.line((px - 9, y - 60, px + 9, y - 40), fill="black", width=2)
                    n = row * 3 + col + 1
                    label(x + 180, y - 92, f"{24 + n}' - 6\"", 25, True)
                    label(x + 50, y + 100, f"ROOM {n:02d}", 24)
                    label(x + 260, y + 100, f"OFFICE {n:02d}", 24)
                    label(x + 260, y + 180, f"AREA {185 + n * 12} SF", 21)
                    label(x + 260, y + 330, f"FLOOR +{n}.25", 20)
                    label(x, y + 455, f"W{n:02d}: 6 inch reinforced wall", 21)
                    label(x, y + 487, f"F{n:02d}: footing 36 x 18 inches", 21)
                    label(x, y + 519, f"B{n:02d}: beam W12 x 26", 21)
            label(160, 3130, "DETAILS ARE SYNTHETIC. VERIFY DIMENSIONS AGAINST SOURCE PIXELS.", 26)
        path = target / f"{kind}.png"
        page.save(path, dpi=(300, 300))
        truth = "\n".join(ground_truth) + "\n"
        (target / f"{kind}.txt").write_text(truth)
        manifest.append({
            "name": kind,
            "width": page.width,
            "height": page.height,
            "pixels": page.width * page.height,
            "png_bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "ground_truth_sha256": hashlib.sha256(truth.encode()).hexdigest(),
        })
    dump(ROOT / "fixtures.json", {"pages": manifest, "generation_seconds": time.perf_counter() - started})
    return manifest


def cgroup(name):
    path = Path("/sys/fs/cgroup") / name
    return path.read_text().strip() if path.exists() else None


def cgroup_cpu():
    return {key: int(value) for key, value in (line.split() for line in cgroup("cpu.stat").splitlines())}


def run_job(case_name, omp, kind, index, timeout=180):
    output_dir = ROOT / "outputs" / case_name
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{index:02d}-{kind}"
    env = dict(os.environ)
    env.pop("OMP_NUM_THREADS", None)
    env.pop("OMP_THREAD_LIMIT", None)
    if omp != "unset":
        env["OMP_THREAD_LIMIT"] = str(omp)
    args = ["tesseract", str(ROOT / "fixtures" / f"{kind}.png"), "stdout", "-l", "eng", "--psm", "3"]
    started = time.perf_counter()
    timed_out = False
    with output.with_suffix(".txt").open("wb") as out, output.with_suffix(".stderr").open("wb") as err:
        proc = subprocess.Popen(args, stdout=out, stderr=err, env=env, start_new_session=True)
        while True:
            waited, status, usage = os.wait4(proc.pid, os.WNOHANG)
            if waited:
                proc.returncode = os.waitstatus_to_exitcode(status)
                break
            if time.perf_counter() - started > timeout:
                timed_out = True
                os.killpg(proc.pid, signal.SIGKILL)
                _, status, usage = os.wait4(proc.pid, 0)
                proc.returncode = os.waitstatus_to_exitcode(status)
                break
            time.sleep(0.01)
    elapsed = time.perf_counter() - started
    return {
        "index": index,
        "page": kind,
        "wall_seconds": elapsed,
        "cpu_user_seconds": usage.ru_utime,
        "cpu_system_seconds": usage.ru_stime,
        "max_rss_kib": usage.ru_maxrss,
        "exit_code": proc.returncode,
        "timed_out": timed_out,
        **quality(
            (ROOT / "fixtures" / f"{kind}.txt").read_text(),
            output.with_suffix(".txt").read_text(),
        ),
    }


def run_case(name, omp, workers, jobs):
    readings = []
    stop = threading.Event()

    def monitor():
        while not stop.is_set():
            readings.append(int(cgroup("memory.current")))
            stop.wait(0.025)

    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    before_cpu = cgroup_cpu()
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda arg: run_job(name, omp, *arg), [(kind, i) for i, kind in enumerate(jobs)]))
    wall = time.perf_counter() - started
    after_cpu = cgroup_cpu()
    stop.set()
    monitor_thread.join()
    row = {
        "case": name,
        "omp_thread_limit": omp,
        "workers": workers,
        "jobs": len(jobs),
        "wall_seconds": wall,
        "pages_per_minute": len(jobs) * 60 / wall,
        "sum_child_cpu_seconds": sum(
            r["cpu_user_seconds"] + r["cpu_system_seconds"] for r in results
        ),
        "peak_cgroup_memory_bytes_sampled": max(readings),
        "cpu_stat_delta": {k: v - before_cpu[k] for k, v in after_cpu.items()},
        "results": results,
    }
    dump(ROOT / f"{name}.json", row)
    print(json.dumps({k: v for k, v in row.items() if k not in ("results", "cpu_stat_delta")}), flush=True)
    return row


def preprocessing():
    import pymupdf
    source = ROOT / "fixtures" / "drawing.png"
    img = Image.open(source)
    timings = []
    for _ in range(3):
        started = time.perf_counter()
        # 30% of width times 70% of height = 21% of pixels, then 2x both axes.
        crop = img.crop((0, 0, round(img.width * .3), round(img.height * .7)))
        resized = crop.resize((crop.width * 2, crop.height * 2), Image.Resampling.LANCZOS)
        resized.save(ROOT / "fixtures" / "drawing-crop-2x.png")
        timings.append(time.perf_counter() - started)
    pdf = pymupdf.open()
    page = pdf.new_page(width=576, height=792)
    page.insert_image(page.rect, filename=str(source))
    pdf.save(ROOT / "fixtures" / "drawing.pdf")
    render = []
    for _ in range(3):
        started = time.perf_counter()
        with pymupdf.open(ROOT / "fixtures" / "drawing.pdf") as document:
            pixels = document[0].get_pixmap(dpi=300)
            pixels.save(ROOT / "fixtures" / "drawing-render.png")
        render.append(time.perf_counter() - started)
    dump(ROOT / "preprocessing.json", {
        "crop_and_2x_resize_and_png_save_seconds": timings,
        "pdf_open_300dpi_render_and_png_save_seconds": render,
        "source_pixels": img.width * img.height,
        "cropped_pixels": crop.width * crop.height,
        "resized_pixels": resized.width * resized.height,
        "resized_source_pixel_ratio": resized.width * resized.height / (img.width * img.height),
        "render_dimensions": [pixels.width, pixels.height],
        "note": (
            "Synthetic PDF contains the same raster image. These are preprocessing "
            "wall times, not model vision or document interpretation measurements."
        ),
    })


def main():
    global ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("pilot", "matrix", "repeat", "summarize"))
    parser.add_argument("--output-dir", type=Path, default=ROOT)
    args = parser.parse_args()
    ROOT = args.output_dir.resolve()
    ROOT.mkdir(parents=True, exist_ok=True)
    if args.mode == "pilot":
        generate()
        dump(ROOT / "environment.json", {
            "python": os.sys.version,
            "tesseract": subprocess.run(
                ["tesseract", "--version"], capture_output=True, text=True, check=True
            ).stdout,
            "cpu_max": cgroup("cpu.max"),
            "memory_max": cgroup("memory.max"),
            "visible_cpu_count": os.cpu_count(),
            "omp_thread_limit": os.getenv("OMP_THREAD_LIMIT"),
            "omp_num_threads": os.getenv("OMP_NUM_THREADS"),
            "first_invocation_note": (
                "First OCR invocation in this benchmark container; "
                "OS page caches are uncontrolled and were not evicted."
            ),
        })
        run_case("pilot-first-unset", "unset", 1, ["text"])
        run_case("pilot-repeat-unset", "unset", 1, ["text"])
        run_case("pilot-repeat-one", "1", 1, ["text"])
        preprocessing()
    elif args.mode in ("matrix", "repeat"):
        limits = ("unset", "1", "2", "4") if args.mode == "matrix" else ("unset", "1")
        configs = [(omp, workers) for omp in limits for workers in (1, 2, 4, 6)]
        random.Random(20260908).shuffle(configs)
        for omp, workers in configs:
            name = f"{args.mode}-omp-{omp}-workers-{workers}"
            if not (ROOT / f"{name}.json").exists():
                run_case(name, omp, workers, ["text", "table", "drawing"] * 2)
    else:
        rows = [json.loads(p.read_text()) for p in sorted(ROOT.glob("*.json")) if p.name.startswith(("matrix-", "repeat-", "pilot-"))]
        all_hashes = {}
        for row in rows:
            for result in row["results"]:
                all_hashes.setdefault(result["page"], set()).add(result["text_sha256"])
        expected = {f"matrix-omp-{omp}-workers-{workers}": 6 for omp in ("unset", "1", "2", "4") for workers in (1, 2, 4, 6)}
        expected.update({f"repeat-omp-{omp}-workers-{workers}": 6 for omp in ("unset", "1") for workers in (1, 2, 4, 6)})
        expected.update({f"pilot-{name}": 1 for name in ("first-unset", "repeat-unset", "repeat-one")})
        missing = sorted(set(expected) - {row["case"] for row in rows})
        invalid = [row["case"] for row in rows if expected.get(row["case"]) != len(row["results"]) or row["jobs"] != len(row["results"])]
        success = bool(rows) and not invalid and all(r["exit_code"] == 0 and not r["timed_out"] for row in rows for r in row["results"])
        dump(ROOT / "summary.json", {
            "cases": rows,
            "missing_cases": missing,
            "invalid_cases": invalid,
            "unique_output_hashes_by_page": {k: sorted(v) for k, v in all_hashes.items()},
            "all_success": success,
            "complete": not missing and success,
            "quality_note": (
                "Token multiset recall/precision measures recovery of known text, "
                "not reading order, geometry, reasoning, or model vision quality. "
                "Six mixed jobs measure batch makespan, not a steady-state throughput "
                "guarantee. Cgroup memory is sampled and includes Python and file cache; "
                "child max RSS is recorded separately."
            ),
        })
        with (ROOT / "summary.csv").open("w") as handle:
            fields = ["case", "omp_thread_limit", "workers", "jobs", "wall_seconds", "pages_per_minute", "sum_child_cpu_seconds", "peak_cgroup_memory_bytes_sampled"]
            writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        print(json.dumps({"cases": len(rows), "missing_cases": missing, "complete": not missing and success, "unique_output_hashes_by_page": {k: len(v) for k, v in all_hashes.items()}}))
        if missing or not success:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
