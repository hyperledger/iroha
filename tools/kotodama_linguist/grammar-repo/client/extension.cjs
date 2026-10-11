"use strict";
const vscode = require("vscode");
const fs = require("node:fs");
const path = require("node:path");
const { LanguageClient } = require("vscode-languageclient/node");
const { serverConfiguration, isProjectManifest, testRunConfiguration } = require("./config.cjs");
const clients = new Map();
let restartPromise = Promise.resolve();

async function startFolder(context, folder) {
  const key = folder ? folder.uri.toString() : "untitled";
  if (clients.has(key)) return;
  const settings = vscode.workspace.getConfiguration("kotodama", folder?.uri);
  let config;
  try {
    config = serverConfiguration(folder?.uri.fsPath, {
      kotoPath: settings.get("kotoPath"), musubiPath: settings.get("musubiPath"),
      manifestPath: folder && settings.get("manifestPath"),
      contract: folder && settings.get("contract"), zk: settings.get("zk"),
      chainDiscriminant: settings.get("chainDiscriminant"),
    }, fs.existsSync);
  } catch (error) {
    await vscode.window.showErrorMessage(error.message);
    return;
  }
  const selector = folder
    ? [{ language: "kotodama", scheme: "file", pattern: new vscode.RelativePattern(folder, "**/*.ko") }]
    : [{ language: "kotodama", scheme: "untitled" }];
  const watchers = folder ? [
    vscode.workspace.createFileSystemWatcher(new vscode.RelativePattern(folder, "**/*.{ko,to}")),
    vscode.workspace.createFileSystemWatcher(new vscode.RelativePattern(folder, "**/{Musubi.toml,Musubi.lock}")),
    ...(config.manifest ? [vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(path.dirname(config.manifest), "{Musubi.toml,Musubi.lock}"))] : []),
  ] : [];
  const client = new LanguageClient(`kotodama:${key}`, "Kotodama", {
    command: config.command, args: config.args, options: { cwd: folder?.uri.fsPath },
  }, {
    documentSelector: selector, workspaceFolder: folder,
    synchronize: { fileEvents: watchers },
  });
  clients.set(key, { client, watchers });
  try {
    await client.start();
    // The project resolver accepts graph-owned manifest buffers. Keep TOML language
    // providers independent; rename checks the exact captured text and document version.
    const matches = document => isProjectManifest(config.manifest, document);
    const opened = new Set();
    let notifications = Promise.resolve();
    const send = (method, params) => {
      notifications = notifications.then(() => client.sendNotification(method, params))
        .catch(error => client.error("Failed to synchronize the Kotodama project manifest", error));
    };
    const open = document => {
      if (!matches(document) || opened.has(document.uri.toString())) return;
      opened.add(document.uri.toString());
      send("textDocument/didOpen", { textDocument: { uri: document.uri.toString(), languageId: "toml", version: document.version, text: document.getText() } });
    };
    watchers.push(vscode.workspace.onDidOpenTextDocument(open));
    watchers.push(vscode.workspace.onDidChangeTextDocument(event => {
      if (!matches(event.document)) return;
      if (!opened.has(event.document.uri.toString())) { open(event.document); return; }
      send("textDocument/didChange", { textDocument: { uri: event.document.uri.toString(), version: event.document.version }, contentChanges: [{ text: event.document.getText() }] });
    }));
    watchers.push(vscode.workspace.onDidCloseTextDocument(document => {
      if (!opened.delete(document.uri.toString())) return;
      send("textDocument/didClose", { textDocument: { uri: document.uri.toString() } });
    }));
    for (const document of vscode.workspace.textDocuments) open(document);
  } catch (error) {
    clients.delete(key);
    watchers.forEach(watcher => watcher.dispose());
    await vscode.window.showErrorMessage(`Kotodama could not start ${config.command}: ${error.message}. Install matching koto and musubi executables or configure their paths.`);
  }
}

async function stopAll() {
  const previous = [...clients.values()];
  clients.clear();
  await Promise.allSettled(previous.map(async ({ client, watchers }) => {
    watchers.forEach(watcher => watcher.dispose());
    await client.stop();
  }));
}

async function activate(context) {
  const start = async () => {
    for (const folder of vscode.workspace.workspaceFolders || []) await startFolder(context, folder);
    await startFolder(context, undefined);
  };
  const restart = () => {
    restartPromise = restartPromise.then(async () => { await stopAll(); await start(); });
    return restartPromise;
  };
  context.subscriptions.push(vscode.commands.registerCommand("kotodama.restart", restart));
  // Both servers attach a typed "Run test" lens that preserves the selected source graph.
  context.subscriptions.push(vscode.commands.registerCommand("kotodama.runTest", async lens => {
    const folder = lens && lens.uri ? vscode.workspace.getWorkspaceFolder(vscode.Uri.parse(lens.uri)) : undefined;
    const settings = vscode.workspace.getConfiguration("kotodama", folder?.uri);
    const run = testRunConfiguration({ kotoPath: settings.get("kotoPath"), musubiPath: settings.get("musubiPath") }, lens);
    const task = new vscode.Task(
      { type: "kotodama", test: lens.name },
      folder ?? vscode.TaskScope.Workspace,
      `test ${lens.name}`,
      "kotodama",
      new vscode.ProcessExecution(run.command, run.args, { cwd: folder?.uri.fsPath }),
    );
    await vscode.tasks.executeTask(task);
  }));
  context.subscriptions.push(vscode.workspace.onDidChangeConfiguration(event => {
    if (event.affectsConfiguration("kotodama")) void restart();
  }));
  context.subscriptions.push(vscode.workspace.onDidChangeWorkspaceFolders(() => { void restart(); }));
  // A newly created project manifest changes which executable owns this folder.
  const manifests = vscode.workspace.createFileSystemWatcher("**/Musubi.toml");
  context.subscriptions.push(manifests, manifests.onDidCreate(() => { void restart(); }),
    manifests.onDidDelete(() => { void restart(); }));
  await start();
}
async function deactivate() { await restartPromise; await stopAll(); }
module.exports = { activate, deactivate };
