# PhiCortex managed CPU baseline (experimental)

This is **not** an independently certified GPU-inactivity test. It launches an installed **local** llama.cpp `llama-server` process with `--n-gpu-layers 0`, `--device none`, `--offline`, `--host 127.0.0.1`, a temporary API key, a fixed single request slot, and explicit context/threads. It does **not** install or download runtimes or models. The managed server is stopped after the benchmark, including when startup fails.

## Prerequisites

1. Install a trusted local `llama-server.exe`/`llama-server` release manually. Check the upstream release/CLI flags for your exact version.
2. Download a locally licensed GGUF instruct model and keep its filepath handy. Model paths must be local; remote model URLs are unsupported.
3. Install Python 3.11 or later; no new Python packages are required.
4. Create a dataset of known-answer tasks. The shipped `benchmarks/cases.example.json` is a **public smoke test**, not a held-out intelligence benchmark.

## Run on Windows PowerShell

```powershell
$env:PYTHONPATH = 'src'
python -m phicortex.cpu_probe `
  --server 'C:\path\to\llama-server.exe' `
  --model 'C:\path\to\instruct.Q4_K_M.gguf' `
  --cases 'benchmarks/cases.example.json' `
  --out 'artifacts/cpu-baseline.json' `
  --threads 4 --context 2048 --max-tokens 64
```

Linux uses identical arguments with POSIX paths and `PYTHONPATH=src`.

Read `artifacts/cpu-baseline.json`. It includes the GGUF and runtime SHA-256, configured CPU/offline flags, OS and logical CPU count, startup and response latency, optional backend token usage, and per-case pass/fail evidence. The API key is **redacted**. Reports do not store raw prompts or generated replies. The original `evaluate.py` known-answer logic is reused, and no production routing or weights are changed.

**Limitations:**
- `--device none` and zero GPU-offloaded layers are *requested* flags, not a separate GPU utilization measurement. GPU inactivity, power, CPU utilization, and RAM peak require independent hardware instrumentation.
- `--offline` is an application flag, not an OS-level networking sandbox; a network-isolated host/test environment is needed to independently prove offline operation.
- The benchmark counts *end-to-end* latency including prompt processing, not just decode time. Backend completion tokens, when reported, support a coarse end-to-end throughput indicator only.
- Public example cases should not support model promotions or superintelligence claims. For real comparisons, use independently assembled private held-out tasks, repeated samples, and fixed model/runtime/context configurations.
- A local process can inspect the temporary API key in its process command line; this is a single-user development harness, not a multi-user service.
- Default loopback port 18943 must be free. Use `--port` to change it.

This harness does not yet manage Ollama. It uses a separately installed standalone llama.cpp server to make the CPU-offload configuration explicit and auditable.
