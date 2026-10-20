// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
#if os(iOS) && !targetEnvironment(macCatalyst)
import AVFoundation
import Foundation
import UIKit

/// Camera callbacks are serialized; stop completion fences all queued callback ownership.
private final class KagemushaQRCamera: NSObject, AVCaptureMetadataOutputObjectsDelegate, @unchecked Sendable {
  enum Failure: Error { case unavailable }
  private let queue = DispatchQueue(label: "org.hyperledger.iroha.probe.qr-camera")
  private var session: AVCaptureSession?
  private var activeOutput: AVCaptureMetadataOutput?
  private var receive: ((String, UInt64) -> Void)?
  func start(receive: @escaping (String, UInt64) -> Void, preview: @escaping (AVCaptureSession) -> Void, failure: @escaping (Error) -> Void) {
    queue.async { [self] in
      guard session == nil, AVCaptureDevice.authorizationStatus(for: .video) == .authorized,
        let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back)
      else { failure(Failure.unavailable); return }
      do {
        let input = try AVCaptureDeviceInput(device: device)
        let output = AVCaptureMetadataOutput()
        let value = AVCaptureSession()
        guard value.canAddInput(input) else { throw Failure.unavailable }
        value.addInput(input)
        guard value.canAddOutput(output) else { throw Failure.unavailable }
        value.addOutput(output)
        guard output.availableMetadataObjectTypes.contains(.qr) else { throw Failure.unavailable }
        output.setMetadataObjectsDelegate(self, queue: queue)
        output.metadataObjectTypes = [.qr]
        self.receive = receive; session = value; activeOutput = output
        value.startRunning()
        guard value.isRunning else { throw Failure.unavailable }
        preview(value)
      } catch { self.receive = nil; activeOutput = nil; session?.stopRunning(); session = nil; failure(error) }
    }
  }
  func stop(completion: @escaping () -> Void) {
    queue.async { [self] in receive = nil; activeOutput = nil; session?.stopRunning(); session = nil; completion() }
  }
  func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject],
                      from connection: AVCaptureConnection) {
    guard output === activeOutput else { return }
    let ticks = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
    for case let object as AVMetadataMachineReadableCodeObject in metadataObjects {
      guard object.type == .qr, let text = object.stringValue, text.utf8.count <= 700,
        text.hasPrefix("IQR1:") || text.hasPrefix("IAK1:") else { continue }
      receive?(text, ticks)
    }
  }
}

/// Disposable visible optical UI. Only the camera object can emit scan observations.
@MainActor final class KagemushaQRPlatform: UIViewController {
  private let image = UIImageView()
  private let message = UILabel()
  private let nextButton = UIButton(type: .system)
  private let cancelButton = UIButton(type: .system)
  private let camera = KagemushaQRCamera()
  private let preview = AVCaptureVideoPreviewLayer()
  private var animation: Timer?
  private var nextAction: (() -> Void)?
  private var closed = false
  private var generation = UUID()
  private weak var selectedScene: UIWindowScene?
  private var lifecycleObservers: [NSObjectProtocol] = []
  private var interrupted = false
  var cancelled: (() -> Void)? { didSet { if interrupted { cancelled?() } } }
  /// Arm before presenting, so foreground loss before the runner attaches is not forgotten.
  func arm(in scene: UIWindowScene) throws {
    guard selectedScene == nil, scene.activationState == .foregroundActive else {
      throw KagemushaQRCamera.Failure.unavailable
    }
    selectedScene = scene
    for (name, object) in [(UIApplication.didEnterBackgroundNotification, nil as AnyObject?),
      (UIScene.didEnterBackgroundNotification, scene), (UIScene.didDisconnectNotification, scene)] {
      lifecycleObservers.append(NotificationCenter.default.addObserver(forName: name,
        object: object, queue: .main) { [weak self] _ in
          Task { @MainActor [weak self] in self?.cancelAttempt() }
        })
    }
  }
  func requireForeground() throws {
    guard !closed, !interrupted, let scene = selectedScene,
      scene.activationState == .foregroundActive, UIApplication.shared.applicationState == .active,
      viewIfLoaded?.window?.windowScene === scene else { throw KagemushaQRCamera.Failure.unavailable }
  }
  override func viewDidLoad() {
    super.viewDidLoad()
    view.backgroundColor = .white
    preview.videoGravity = .resizeAspectFill
    image.layer.addSublayer(preview)
    isModalInPresentation = true
    message.numberOfLines = 0; message.textColor = .black; message.textAlignment = .center
    image.contentMode = .center; image.layer.magnificationFilter = .nearest; image.layer.minificationFilter = .nearest
    nextButton.addTarget(self, action: #selector(advance), for: .touchUpInside)
    cancelButton.setTitle("Cancel QR attempt", for: .normal)
    cancelButton.addTarget(self, action: #selector(cancelAttempt), for: .touchUpInside)
    let layout = UIStackView(arrangedSubviews: [message, image, nextButton, cancelButton])
    layout.axis = .vertical; layout.spacing = 16; layout.translatesAutoresizingMaskIntoConstraints = false
    view.addSubview(layout)
    NSLayoutConstraint.activate([
      layout.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 16),
      layout.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -16),
      layout.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 16),
      layout.bottomAnchor.constraint(lessThanOrEqualTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -16),
      image.heightAnchor.constraint(equalTo: image.widthAnchor),
    ])
  }
  override func viewDidLayoutSubviews() { super.viewDidLayoutSubviews(); preview.frame = image.bounds }
  @objc private func advance() { let action = nextAction; nextAction = nil; nextButton.isEnabled = false; action?() }
  @objc private func cancelAttempt() { interrupted = true; cancelled?() }
  override func viewDidDisappear(_ animated: Bool) {
    super.viewDidDisappear(animated)
    if !closed && (isBeingDismissed || presentingViewController == nil) { cancelAttempt() }
  }
  func scan(label: String, receive: @escaping (String, UInt64) -> Void, failure: @escaping (Error) -> Void) {
    do { try requireForeground() } catch { failure(error); return }
    animation?.invalidate(); animation = nil; image.image = nil; nextButton.isHidden = true; nextAction = nil
    message.text = label + "\nPoint the rear camera at the other phone's QR."
    let token = UUID(); generation = token
    let start = { [weak self] in
      guard let self, !self.closed, self.generation == token else { return }
      self.camera.start(receive: receive, preview: { [weak self] session in
        Task { @MainActor [weak self] in
          guard let self, !self.closed, self.generation == token else { return }
          self.preview.session = session
        }
      }, failure: failure)
    }
    if AVCaptureDevice.authorizationStatus(for: .video) == .notDetermined {
      AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
        Task { @MainActor [weak self] in
          guard let self, !self.closed, self.generation == token else { return }
          do { try self.requireForeground(); guard granted else { throw KagemushaQRCamera.Failure.unavailable }; start() }
          catch { failure(error) }
        }
      }
    } else { start() }
  }
  func stopScan(completion: @escaping () -> Void) {
    generation = UUID(); preview.session = nil; camera.stop(completion: completion)
  }
  /// Completing this action means the local operator changed screens, never peer delivery.
  func display(_ frames: [KagemushaQRRenderedFrame], label: String, nextTitle: String,
               observed: @escaping (Int, UInt64) -> Void, nextAction: @escaping () -> Void) {
    do { try requireForeground(); guard !frames.isEmpty else { throw KagemushaQRCamera.Failure.unavailable } }
    catch { cancelAttempt(); return }
    animation?.invalidate(); animation = nil
    message.text = label; nextButton.isHidden = false; nextButton.isEnabled = true
    nextButton.setTitle(nextTitle, for: .normal); self.nextAction = nextAction
    let token = UUID(); generation = token
    var index = 0
    let show = { [weak self] in
      guard let self, !self.closed, self.generation == token else { return }
      let frame = frames[index]
      // Whole-pixel scale within the measured view; the generator's pixel size is 6/module.
      let width = min(self.image.bounds.width, self.image.bounds.height) * self.traitCollection.displayScale
      let modules = CGFloat(frame.image.width) / 6
      let scale = max(1, floor(width / modules))
      self.image.image = UIImage(cgImage: frame.image, scale: 6 * self.traitCollection.displayScale / scale,
        orientation: .up)
      observed(index, clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW))
      index = (index + 1) % frames.count
    }
    view.layoutIfNeeded(); show()
    if frames.count > 1 {
      animation = Timer.scheduledTimer(withTimeInterval: 0.15, repeats: true) { _ in
        Task { @MainActor in show() }
      }
    }
  }
  /// All camera work drains before the owner sees completion and may release Native custody.
  func close(completion: @escaping () -> Void) {
    guard !closed else { camera.stop(completion: completion); return }
    closed = true; generation = UUID(); preview.session = nil; animation?.invalidate(); animation = nil
    nextAction = nil; cancelled = nil
    lifecycleObservers.forEach(NotificationCenter.default.removeObserver); lifecycleObservers.removeAll()
    camera.stop { [weak self] in Task { @MainActor in
      guard let self else { completion(); return }
      self.dismiss(animated: false, completion: completion)
    }}
  }
}
#endif
