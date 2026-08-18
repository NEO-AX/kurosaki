-- 実データを含まないシード。**ここから1件も検出してはならない。**
-- 応募者の氏名は入れない方針。山田 太郎 のような例示もコメントに留める。
-- 選考 基準 と 面接 段階 の語が漢字2文字ずつ並ぶが、これは氏名ではない。
INSERT INTO seasons (id, label, starts_on) VALUES (2, '2期', '2026-04-01');
INSERT INTO selection_steps (id, season_id, name, ordinal) VALUES (1, 2, '書類選考', 1);
INSERT INTO evaluation_criteria (id, step_id, label) VALUES (1, 1, '論理 構成');
