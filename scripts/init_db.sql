-- ─────────────────────────────────────────────────────────────
-- AegisAI — Database Initialisation
-- Runs automatically when PostgreSQL container starts for the first time
-- ─────────────────────────────────────────────────────────────

-- ── Evaluation Runs ───────────────────────────────────────────
-- Stores results from every evaluation run against the golden dataset
CREATE TABLE IF NOT EXISTS evaluation_runs (
    run_id          TEXT PRIMARY KEY,
    run_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    trigger         TEXT,                          -- 'manual', 'ci', 'nightly'
    model           TEXT NOT NULL,                 -- 'qwen2.5:7b'
    prompt_version  TEXT NOT NULL,                 -- 'v1.0'
    dataset_version TEXT NOT NULL,                 -- 'golden-v1.0'
    chunk_size      INT,
    chunk_overlap   INT,
    top_k           INT,
    similarity_threshold FLOAT,
    total_scenarios INT NOT NULL,
    passed          INT NOT NULL,
    failed          INT NOT NULL,
    -- LLM Quality (DeepEval)
    faithfulness          FLOAT,
    answer_relevancy      FLOAT,
    hallucination_rate    FLOAT,
    contextual_relevancy  FLOAT,
    -- Retrieval Quality (RAGAS)
    context_precision     FLOAT,
    context_recall        FLOAT,
    -- Business Accuracy
    risk_rating_accuracy  FLOAT,
    -- Security
    injection_success_rate FLOAT DEFAULT 0.0,
    -- CI/CD
    gate_status     TEXT,                          -- 'passed', 'failed'
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Scenario Results ──────────────────────────────────────────
-- Stores per-scenario outcomes for each evaluation run
CREATE TABLE IF NOT EXISTS scenario_results (
    id              SERIAL PRIMARY KEY,
    run_id          TEXT NOT NULL REFERENCES evaluation_runs(run_id),
    scenario_id     TEXT NOT NULL,                 -- 'IAM-001'
    category        TEXT NOT NULL,                 -- 'Identity and Access Management'
    passed          BOOLEAN NOT NULL,
    expected_score  INT,
    actual_score    INT,
    expected_rating TEXT,
    actual_rating   TEXT,
    failure_type    TEXT,                          -- 'Business Rule Failure', 'LLM Quality', etc.
    faithfulness    FLOAT,
    answer_relevancy FLOAT,
    context_precision FLOAT,
    context_recall  FLOAT,
    latency_ms      INT,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Document Registry ─────────────────────────────────────────
-- Tracks uploaded knowledge base documents
CREATE TABLE IF NOT EXISTS documents (
    document_id     TEXT PRIMARY KEY,
    document_name   TEXT NOT NULL,
    document_type   TEXT NOT NULL,                 -- 'internal_policy', 'external_reference'
    file_path       TEXT,
    chunk_count     INT,
    embedding_model TEXT,
    chunk_size      INT,
    chunk_overlap   INT,
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Indexes ───────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_evaluation_runs_run_at
    ON evaluation_runs(run_at DESC);

CREATE INDEX IF NOT EXISTS idx_scenario_results_run_id
    ON scenario_results(run_id);

CREATE INDEX IF NOT EXISTS idx_scenario_results_scenario_id
    ON scenario_results(scenario_id);

-- ── Seed message ──────────────────────────────────────────────
DO $$
BEGIN
    RAISE NOTICE 'AegisAI database initialised successfully.';
END $$;
