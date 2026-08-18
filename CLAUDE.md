# CLAUDE.md —— 監査法人側の実装規律

このリポジトリは**監査する側**の道具である。被監査リポジトリではない。
ここを触るAI（および人間）は次を守る。

## 絶対に守る

- **検出を緩める変更をしない。** 閾値を下げる、除外を広げる、手続を消す、
  `continue-on-error` を足す —— これらは「監査を通しやすくする」変更であり、
  成果物の価値をゼロにする。誤検知を直す場合は、**誤検知が消えて検出が残ること**を
  テストで示してから直す。
- **出力に生の個人情報・秘密を載せない。** 外へ出る文字列は `mask.py` を通す。
  `tests/test_scan.py` と `tests/test_audit.py` がこれを固定している。
- **fail closed。** 走査できない・解釈できない・確認できないときは、緩めずに
  「所見」または「実施不能」にする。「たぶん大丈夫」は書かない。
- **手続を足したら期待表も足す。** `tests/test_audit.py` の `EXPECT_ON_BROKEN` と
  `tests/test_bypass.py` の `EXPECTED` を更新しないとテストが落ちる（意図的な設計）。
- **すり抜け経路を隠さない。** 残存リスクは `docs/BYPASS_DRILL.md` に書く。
  「解消した」と書くには、試験で止まることを示す。

## 依存

- Python 標準ライブラリのみ。追加依存を入れない（被監査環境に何があるか分からない）。
- `gh` / `Faker` は「あれば使う」。無い場合は緩和を無効にする側へ倒す。

## 完了条件

```
python3 -m unittest discover -s tests -p 'test_*.py'   # 全件 pass
python3 tests/bypass_drill.py                          # 停止点の表が期待どおり
kurosaki audit --repo <このリポジトリ>                   # 自分自身の監査で Critical/High ゼロ
```

## 不可逆操作

`.audit/IRREVERSIBLE_OPS.md` を見る。被監査リポジトリへの `install`、被監査リポジトリの
履歴改変、公開設定の変更は、この道具の側からは実行しない（提案までに留める）。

<!-- kurosaki:begin —— この区画は監査法人が管理する。実装セッションで編集しないこと。 -->
## 監査基盤（編集禁止）

このリポジトリには独立した監査基盤が入っている。実装を担当するAIは次を守る。

- **`.audit/` と `.githooks/` と `.github/workflows/audit.yml` を編集しない。**
  変更は `.audit/MANIFEST.sha256` との照合（D7-01）とCIのジョブBで検知され、必ず落ちる。
- **seed / fixture / テスト / デモ / スクリーンショットに実在の個人情報を使わない。**
  ダミーは `Faker(ja_JP)` で生成する。実データは git の外に置く。
- **不可逆操作を実行しない。** 一覧と承認手順は `.audit/IRREVERSIBLE_OPS.md`。
  該当する操作は提案までに留め、実行は人間が行う。
- 監査で Critical / High が出ている状態で、commit / push / マージ / デプロイへ進まない。
- 監査を通すために閾値を緩める、allowlist を広げる、`continue-on-error` を足す、
  `--no-verify` を使う —— これらはすべて禁止であり、いずれも検知される。

自分で監査を回す場合:

```
kurosaki scan  --repo .            # 個人情報・秘密の走査
kurosaki audit --repo .            # 体制監査（意見が出る）
```
<!-- kurosaki:end -->
