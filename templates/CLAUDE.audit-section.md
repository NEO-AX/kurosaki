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
