-- 架空データ。pg_dump のテキスト形式（COPY）で持ち出された場合の検出試験。
COPY youth_candidates (id, name, mail, phone) FROM stdin;
7	仮想 三郎	saburo@kasou-oubo.co.jp	080-9876-5432
8	想像 四郎	shiro@kasou-oubo.co.jp	090-1111-2222
\.
