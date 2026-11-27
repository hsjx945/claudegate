import AppKit
import Foundation

guard CommandLine.arguments.count >= 2 else {
    fputs("Usage: generate-icon <output.iconset>\n", stderr)
    exit(1)
}

let outDir = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)

let entries: [(String, Int)] = [
    ("icon_16x16.png", 16),
    ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32),
    ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512),
    ("icon_512x512@2x.png", 1024),
]

for (filename, px) in entries {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: px,
        pixelsHigh: px,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    )!

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

    let size = CGFloat(px)
    let rect = NSRect(x: 0, y: 0, width: size, height: size)
    let inset = size * 0.06
    let cardRect = rect.insetBy(dx: inset, dy: inset)
    let radius = size * 0.22
    let path = NSBezierPath(roundedRect: cardRect, xRadius: radius, yRadius: radius)

    let gradient = NSGradient(colors: [
        NSColor(red: 0.08, green: 0.13, blue: 0.22, alpha: 1.0),
        NSColor(red: 0.04, green: 0.07, blue: 0.12, alpha: 1.0),
    ])!
    gradient.draw(in: path, angle: -90)

    NSColor(red: 0.22, green: 0.55, blue: 0.95, alpha: 0.45).setStroke()
    path.lineWidth = max(1.0, size * 0.025)
    path.stroke()

    if let sym = NSImage(systemSymbolName: "checkmark.shield.fill", accessibilityDescription: nil) {
        let cfg = NSImage.SymbolConfiguration(pointSize: size * 0.50, weight: .semibold)
            .applying(NSImage.SymbolConfiguration(paletteColors: [
                NSColor(red: 0.24, green: 0.85, blue: 0.52, alpha: 1.0)
            ]))
        let img = sym.withSymbolConfiguration(cfg) ?? sym
        let imgSize = img.size
        let drawW = size * 0.56
        let drawH = drawW * (imgSize.height / max(1, imgSize.width))
        let drawRect = NSRect(
            x: (size - drawW) / 2,
            y: (size - drawH) / 2,
            width: drawW,
            height: drawH
        )
        img.draw(in: drawRect)
    }

    NSGraphicsContext.restoreGraphicsState()

    if let pngData = rep.representation(using: .png, properties: [:]) {
        try pngData.write(to: outDir.appendingPathComponent(filename))
    }
}
