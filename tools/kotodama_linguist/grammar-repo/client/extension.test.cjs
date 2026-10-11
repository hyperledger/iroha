"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

test("binary contract changes reach the owning language server without opening binary documents", async () => {
  const instances = [];
  const watchers = [];
  const disposable = () => ({ dispose() { this.disposed = true; } });
  class RelativePattern {
    constructor(base, pattern) { this.base = base; this.pattern = pattern; }
  }
  const folder = { uri: { fsPath: "/workspace", toString: () => "file:///workspace" } };
  const vscode = {
    RelativePattern,
    workspace: {
      workspaceFolders: [folder], textDocuments: [],
      getConfiguration: () => ({ get: () => undefined }),
      createFileSystemWatcher(pattern) {
        const watcher = { ...disposable(), pattern, onDidCreate: disposable, onDidDelete: disposable };
        watchers.push(watcher);
        return watcher;
      },
      onDidOpenTextDocument: disposable, onDidChangeTextDocument: disposable,
      onDidCloseTextDocument: disposable, onDidChangeConfiguration: disposable,
      onDidChangeWorkspaceFolders: disposable,
    },
    commands: { registerCommand: disposable },
    window: { showErrorMessage(message) { assert.fail(message); } },
  };
  class LanguageClient {
    constructor(id, name, server, options) { Object.assign(this, { id, name, server, options }); instances.push(this); }
    async start() {}
    async stop() { this.stopped = true; }
  }
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "extension.cjs"), "utf8"), {
    module,
    require(name) {
      if (name === "vscode") return vscode;
      if (name === "vscode-languageclient/node") return { LanguageClient };
      if (name === "node:fs") return { existsSync: () => false };
      if (name === "./config.cjs") return require("./config.cjs");
      return require(name);
    },
  });
  await module.exports.activate({ subscriptions: [] });
  const client = instances.find(value => value.id === "kotodama:file:///workspace");
  assert.ok(client);
  assert.equal(client.options.documentSelector[0].pattern.pattern, "**/*.ko");
  const binaryWatcher = watchers.find(value => value.pattern.pattern === "**/*.{ko,to}");
  assert.ok(binaryWatcher);
  assert.ok(client.options.synchronize.fileEvents.includes(binaryWatcher));
  await module.exports.deactivate();
  assert.equal(binaryWatcher.disposed, true);
  assert.equal(client.stopped, true);
});
