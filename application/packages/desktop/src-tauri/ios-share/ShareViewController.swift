import UIKit
import UniformTypeIdentifiers

/// The iOS share extension: PrivacyNotes in the system share sheet.
///
/// It runs in its own process and cannot reach the app, and it never holds the
/// keys. It writes what it was given into the app group's inbox, and the app
/// takes it from there once the user has signed in and cleared the app lock,
/// which is where the item is encrypted like any other. Until then each file
/// carries complete data protection, so iOS keeps it encrypted while the phone
/// is locked, and the app deletes it as soon as it has taken it.
///
/// Picking PrivacyNotes saves at once: a card shows a spinner, then "Saved to
/// PrivacyNotes", the size limit, or the failure text, and closes itself. A share extension
/// cannot open its app, so the card is how the user learns it landed; the
/// system compose sheet was not used because it hides itself on Post, before
/// a confirmation could show. The three texts come from the web catalogs: the
/// version script writes them into the .lproj folders beside this file.
/// Spec: ops/docs/plans/share-into-app.md
final class ShareViewController: UIViewController {
    private static let appGroup = "group.app.privacynotes"
    /// The largest per-file limit the app grants (the storage add-on); the app's
    /// own check names the lower limits to the user. src/share_inbox.rs holds the
    /// same cap.
    private static let maxFileBytes = 100 * 1000 * 1000
    /// The app's own cap on a shared text; past it, the text is cut here.
    private static let maxTextChars = 500_000
    /// Each folder is created with complete protection, so the files written into
    /// it inherit the class from their first byte.
    private static let protectedFolder: [FileAttributeKey: Any] = [.protectionKey: FileProtectionType.complete]
    private static let maxFiles = 10
    private static let stamp: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH.mm.ss"
        return f
    }()

    /// What the card tells the user. `tooLarge` wins over `saved`: a share of
    /// several files where some were over the limit saves the rest, and the user
    /// must still learn that some did not arrive.
    private enum Outcome {
        case saved
        case tooLarge(limit: Int)
        case failed
    }

    private enum FileResult { case saved, tooLarge, failed }

    private let card = UIVisualEffectView(effect: UIBlurEffect(style: .systemMaterial))
    private let stack = UIStackView()
    private var started = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor.black.withAlphaComponent(0.2)
        let spinner = UIActivityIndicatorView(style: .large)
        spinner.startAnimating()
        stack.addArrangedSubview(spinner)
        stack.axis = .vertical
        stack.alignment = .center
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false
        card.layer.cornerRadius = 18
        card.clipsToBounds = true
        card.translatesAutoresizingMaskIntoConstraints = false
        card.contentView.addSubview(stack)
        view.addSubview(card)
        NSLayoutConstraint.activate([
            card.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            card.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            card.widthAnchor.constraint(lessThanOrEqualToConstant: 260),
            card.widthAnchor.constraint(greaterThanOrEqualToConstant: 180),
            stack.topAnchor.constraint(equalTo: card.contentView.topAnchor, constant: 24),
            stack.bottomAnchor.constraint(equalTo: card.contentView.bottomAnchor, constant: -24),
            stack.leadingAnchor.constraint(equalTo: card.contentView.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: card.contentView.trailingAnchor, constant: -20),
        ])
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard !started else { return }
        started = true
        let items = extensionContext?.inputItems as? [NSExtensionItem] ?? []
        Task {
            let outcome = await Self.save(items: items)
            await self.confirm(outcome)
            self.extensionContext?.completeRequest(returningItems: nil)
        }
    }

    private func confirm(_ outcome: Outcome) async {
        let message: String
        let symbol: String
        let tint: UIColor
        let seconds: Double
        switch outcome {
        case .saved:
            (message, symbol, tint, seconds) = (NSLocalizedString("saved", comment: ""), "checkmark.circle.fill", .systemGreen, 0.9)
        case .tooLarge(let limit):
            let megabytes = String(max(1, limit / 1_000_000))
            let text = NSLocalizedString("tooLarge", comment: "").replacingOccurrences(of: "{{limit}}", with: megabytes)
            (message, symbol, tint, seconds) = (text, "exclamationmark.triangle.fill", .systemOrange, 2.2)
        case .failed:
            (message, symbol, tint, seconds) = (NSLocalizedString("failed", comment: ""), "exclamationmark.circle.fill", .systemRed, 1.8)
        }
        let icon = UIImageView(image: UIImage(systemName: symbol))
        icon.tintColor = tint
        icon.preferredSymbolConfiguration = UIImage.SymbolConfiguration(pointSize: 44, weight: .semibold)
        let label = UILabel()
        label.text = message
        label.font = .preferredFont(forTextStyle: .headline)
        label.adjustsFontForContentSizeCategory = true
        label.numberOfLines = 0
        label.textAlignment = .center
        stack.arrangedSubviews.forEach { $0.removeFromSuperview() }
        stack.addArrangedSubview(icon)
        stack.addArrangedSubview(label)
        UIAccessibility.post(notification: .announcement, argument: message)
        try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
    }

    /// The signed-in account's per-file limit, which the app writes beside the
    /// inbox after each quota read (src/share_inbox.rs, "ShareLimit"). Before the
    /// app has run, the largest limit it grants, and the app's own upload check
    /// names the lower ones.
    private static func accountLimit(_ group: URL) -> Int {
        guard let text = try? String(contentsOf: group.appendingPathComponent("ShareLimit"), encoding: .utf8),
              let limit = Int(text.trimmingCharacters(in: .whitespacesAndNewlines)), limit > 0
        else { return maxFileBytes }
        return min(limit, maxFileBytes)
    }

    private static func save(items: [NSExtensionItem]) async -> Outcome {
        guard let group = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
        else { return .failed }
        let inbox = group.appendingPathComponent("ShareInbox", isDirectory: true)
        let limit = accountLimit(group)
        try? FileManager.default.createDirectory(at: inbox, withIntermediateDirectories: true, attributes: protectedFolder)
        let providers = items.flatMap { $0.attachments ?? [] }
        // Safari puts the page title (or a selection) in the item's own text.
        let itemText = items.compactMap { ($0.attributedContentText ?? $0.attributedTitle)?.string }
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .first { !$0.isEmpty }
        var urls: [URL] = []
        var texts: [String] = []
        var files = 0
        var tooLarge = 0

        // The activation rule admits at most a link and ten files, so anything past
        // that is a sender ignoring it; it is not read at all.
        for provider in providers.prefix(maxFiles + 1) {
            if let url = await webURL(provider) {
                urls.append(url)
            } else if let text = await plainText(provider) {
                texts.append(text)
            } else if files < maxFiles, let type = fileType(provider) {
                switch await saveFile(provider, type: type, index: files, limit: limit, inbox: inbox) {
                case .saved: files += 1
                case .tooLarge: tooLarge += 1
                case .failed: break
                }
            }
        }

        // A link keeps the page title; text becomes a note, or, with no text
        // attachment, the item's own text does.
        let shared = texts.joined(separator: "\n\n").trimmingCharacters(in: .whitespacesAndNewlines)
        var written = files
        for url in urls {
            let title = itemText ?? (shared == url.absoluteString ? "" : shared)
            if write(["kind": "url", "url": url.absoluteString, "title": String(title.prefix(maxTextChars))], inbox: inbox) { written += 1 }
        }
        let note = shared.isEmpty && files == 0 ? (itemText ?? "") : shared
        if urls.isEmpty && !note.isEmpty {
            if write(["kind": "text", "text": String(note.prefix(maxTextChars))], inbox: inbox) { written += 1 }
        }
        if tooLarge > 0 { return .tooLarge(limit: limit) }
        return written > 0 ? .saved : .failed
    }

    private static func plainText(_ provider: NSItemProvider) async -> String? {
        guard provider.hasItemConformingToTypeIdentifier(UTType.plainText.identifier),
              !provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier),
              let item = try? await provider.loadItem(forTypeIdentifier: UTType.plainText.identifier)
        else { return nil }
        if let text = item as? String { return text }
        if let data = item as? Data { return String(data: data, encoding: .utf8) }
        return nil
    }

    private static func webURL(_ provider: NSItemProvider) async -> URL? {
        guard provider.hasItemConformingToTypeIdentifier(UTType.url.identifier),
              !provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier),
              let item = try? await provider.loadItem(forTypeIdentifier: UTType.url.identifier),
              let url = item as? URL,
              url.scheme == "http" || url.scheme == "https"
        else { return nil }
        return url
    }

    /// The type to read a file as: the first registered type that is data and
    /// not text, which the compose text already carries.
    private static func fileType(_ provider: NSItemProvider) -> UTType? {
        provider.registeredContentTypes.first {
            $0.conforms(to: .data) && !$0.conforms(to: .plainText) && !$0.conforms(to: .url)
        }
    }

    /// The original size is what counts, as in the app: its upload checks the
    /// file before it shrinks a picture.
    private static func saveFile(_ provider: NSItemProvider, type: UTType, index: Int, limit: Int, inbox: URL) async -> FileResult {
        let id = UUID().uuidString
        let tmp = inbox.appendingPathComponent(".tmp-\(id)", isDirectory: true)
        var overLimit = false
        // The copy's own name, when the sender gives no suggested one: Files and
        // Mail hand over a copy that keeps the original file name.
        let copiedName: String?? = await withCheckedContinuation { done in
            // The system deletes `source` when this handler returns, so the copy
            // happens inside it.
            _ = provider.loadFileRepresentation(forTypeIdentifier: type.identifier) { source, _ in
                guard let source,
                      let size = try? source.resourceValues(forKeys: [.fileSizeKey]).fileSize,
                      size > 0
                else { done.resume(returning: nil); return }
                guard size <= limit else {
                    overLimit = true
                    done.resume(returning: nil)
                    return
                }
                do {
                    try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true, attributes: protectedFolder)
                    let payload = tmp.appendingPathComponent("payload")
                    try FileManager.default.copyItem(at: source, to: payload)
                    // A copy can carry the source's own class; set ours explicitly.
                    try protect(payload)
                    let own = source.lastPathComponent
                    done.resume(returning: .some(own.isEmpty ? nil : own))
                } catch {
                    done.resume(returning: nil)
                }
            }
        }
        guard let copiedName else {
            try? FileManager.default.removeItem(at: tmp)
            return overLimit ? .tooLarge : .failed
        }
        let ext = type.preferredFilenameExtension.map { ".\($0)" } ?? ""
        let name: String
        if let given = provider.suggestedName ?? copiedName {
            name = (given as NSString).pathExtension.isEmpty ? given + ext : given
        } else {
            // Photos gives no name. The time of the share reads the same in every
            // language, where a word such as "photo" would need translating; its
            // dots are not an extension, so the type's own is always added.
            let number = index == 0 ? "" : " \(index + 1)"
            name = Self.stamp.string(from: Date()) + number + ext
        }
        let item: [String: Any] = ["kind": "file", "name": name, "mime": type.preferredMIMEType ?? ""]
        return finish(item, tmp: tmp, id: id, inbox: inbox) ? .saved : .failed
    }

    private static func write(_ fields: [String: Any], inbox: URL) -> Bool {
        let id = UUID().uuidString
        let tmp = inbox.appendingPathComponent(".tmp-\(id)", isDirectory: true)
        guard (try? FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true, attributes: protectedFolder)) != nil else {
            return false
        }
        return finish(fields, tmp: tmp, id: id, inbox: inbox)
    }

    /// Writes item.json and renames the folder into place, so the app never
    /// sees an item half written.
    private static func finish(_ fields: [String: Any], tmp: URL, id: String, inbox: URL) -> Bool {
        var item = fields
        item["v"] = 1
        item["created"] = Int(Date().timeIntervalSince1970 * 1000)
        do {
            let json = try JSONSerialization.data(withJSONObject: item)
            try json.write(to: tmp.appendingPathComponent("item.json"), options: [.atomic, .completeFileProtection])
            try FileManager.default.moveItem(at: tmp, to: inbox.appendingPathComponent(id, isDirectory: true))
            return true
        } catch {
            try? FileManager.default.removeItem(at: tmp)
            return false
        }
    }

    private static func protect(_ url: URL) throws {
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
    }
}
