# 專題備審02｜ChatMiniNet / MiniEdit IBN Agent

## 專案介紹

ChatMiniNet / MiniEdit IBN Agent 是以 MiniEdit 為基礎的圖形化網路實驗與 AWS Lab 管理專題。它將拓撲 Canvas、資源 Inspector、對話式 Network Copilot、Containernet 與 AWS 資源生命週期管理整合在同一個桌面操作流程中。

## UI 與系統架構

```text
Tkinter Desktop UI
  ├─ Topology Canvas：呈現本機與 AWS 資源關係
  ├─ Inspector：顯示被選取資源的設定與狀態
  └─ Network Copilot：對話、圖形化控制與進度卡片
       └─ AWS Workspace
            ├─ Architecture / Build Session
            ├─ Catalog / OS catalog
            ├─ Canvas adapter
            └─ Cleanup lifecycle
```

此 repo 保留 UI 元件、深色設計語言、AWS Build/Canvas/Cleanup 核心模型與 JobManager，供閱讀專案主架構與互動設計。

## 安裝說明

此公開版是架構與 UI 展示版，保留核心模型而非所有執行模組。完整原型需要 Linux、Mininet；Containernet、AWS 與 LLM 整合則為選用系統依賴。以下為主要 Python 依賴的安裝方式：

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
sudo .venv/bin/python miniedit_ibn.py
```

## 公開範圍

這是精簡的備審展示版本，不包含 AWS 憑證、`.env`、工作階段資料、日誌、skills、產生內容、攻防實驗資料或完整執行環境，因此不保證能獨立執行所有功能。
