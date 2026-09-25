# Agent Card Scanner Core

[English](README.md) · [CLI仕様](docs/cli.md) · [Web版](https://scan.agentcollusion.ai)

A2A Agent Cardの基本検査と署名検証を行う、**Apache-2.0のOSS CLI／Node.jsライブラリ**です。Agent Card Scannerから単一カードの検査機能を切り出しました。Node.js 22以上で動作し、依存パッケージ・APIキーは不要です。テレメトリはありません。

## すぐ試す

```sh
git clone --branch v0.5.0 https://github.com/agentcollusion/agent-card-scanner-core.git
cd agent-card-scanner-core
node src/cli.mjs verify examples/unsigned-card.json --url https://agent.example.com/card.json --format text
```

架空のカードをオフラインで検査します。署名と認証宣言がないことを参考情報として表示し、標準ポリシーではPASSになります。PASSは選択した検査ポリシーへの適合を示します。エージェントの実行時の安全性や運営者の身元を保証するものではありません。

GitHubのリリースタグからCLIをインストールできます。npmレジストリへの公開は行っていません。

```sh
npm install -g git+https://github.com/agentcollusion/agent-card-scanner-core.git#v0.5.0
agent-card-scanner --help
```

パッケージ名は `agent-card-scanner-core`、コマンド名は `agent-card-scanner` です。従来のサイト配布CLIとコマンド名が共通のため、グローバルに併用すると同じコマンドを置き換えます。

## 公開する基本機能

- ローカルJSON・公開HTTPS URLのAgent Card検査
- 基本フィールド、接続先URL、認証宣言の確認
- 公開JWKSを使った署名検証
- 根拠・修正案を含むJSON／テキスト出力
- CIで利用できる検査ポリシーと終了コード
- Node.jsアプリに組み込めるライブラリ

```sh
# ローカルJSONをオフラインで検査
agent-card-scanner verify agent-card.json --url https://your-agent.example/card.json --format text

# パイプからJSONを渡して検査
cat agent-card.json | agent-card-scanner verify - --url https://your-agent.example/card.json --format text

# 利用者が選んだ公開鍵で署名を必須にする
agent-card-scanner verify agent-card.json --url https://your-agent.example/card.json --jwks public-jwks.json --require-signature

# 公開済みカードを検査
agent-card-scanner check https://your-agent.example/card.json --format json
```

ドメインは実際の公開URLに置き換えてください。終了コードは成功 `0`、ポリシー不適合 `1`、入力エラー `2`、取得失敗などの未完了 `3` です。検査結果・修正案の出力言語は英語です。

`verify -` は標準入力を読み込みます。ファイルと同じ512 KiB制限を適用し、不正なUTF-8やJSONキーの重複を拒否します。PowerShellでは `cat` の代わりに `Get-Content -Raw -Encoding utf8 agent-card.json` を使用できます。接続先URLの問題には `/supportedInterfaces/0/url` などの場所を付け、テキストでも `At:` として表示します。

## 公開範囲と制約

このリポジトリには検査コア、CLI、テスト、レポートのスキーマ、架空のサンプルを含みます。Web/APIの運用基盤、デプロイ設定、一括スキャン・クラスタリング、収集データ、内部資料は含みません。

`verify` は `--network` を指定しない限り通信しません。`check` はカードと対応する公開鍵だけを取得し、エージェントのタスクは実行しません。完全なA2A仕様適合検査、鍵の失効確認、稼働中のエージェントの安全性評価は対象外です。

開発時は依存パッケージのインストールなしで `npm run check` を実行できます。Node.js 22／24のLinux CIでは通信を遮断し、回帰テストと配布パッケージのインストール検証を行います。

詳細は[英語README](README.md)、[CLI仕様](docs/cli.md)、[貢献ガイド](CONTRIBUTING.md)、[脆弱性報告](SECURITY.md)を参照してください。

ライセンス: [Apache-2.0](LICENSE)。Copyright 2026 AgentCollusion。

## カードの更新前後を比較する

```sh
agent-card-scanner compare before.json after.json --format text
```

0.5.0では、スキル・接続先・認証要件・入出力形式・機能の変更をオフラインで比較できます。終了コード1は変更の確認が必要という意味です。実行時の互換性を保証するものではありません。[対象と制限](docs/cli.md#compare-card-updates-locally)を確認してください。[Web版](https://scan.agentcollusion.ai/compare)もブラウザ内で処理します。
