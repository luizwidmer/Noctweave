# Repository Guidelines

## Project Structure & Module Organization
This repo is split into three top-level areas. The SwiftUI client app lives in `PICCP Messaging Client/` with source under `PICCP Messaging Client/PICCP Messaging Client/` and assets in `Assets.xcassets`. The SwiftUI server app mirrors that layout in `PICCP Server/` (`PICCP Server/PICCP Server/`). Project documentation and research materials are in `PICCP Documentation/` (e.g., `piccp_whitepaper.md`, roadmap PDFs).

## Build, Test, and Development Commands
Use Xcode for day-to-day development and simulator/device runs.
- Open the client app: `open "PICCP Messaging Client/PICCP Messaging Client.xcodeproj"`
- Open the server app: `open "PICCP Server/PICCP Server.xcodeproj"`
- Build from CLI (client): `xcodebuild -project "PICCP Messaging Client/PICCP Messaging Client.xcodeproj" -scheme "Noctyra" build`
- Build from CLI (server): `xcodebuild -project "PICCP Server/PICCP Server.xcodeproj" -scheme "Noctyra Relay" build`
Run `xcodebuild -list -project <path>` if you need to confirm schemes.

## Coding Style & Naming Conventions
Follow standard Swift/Xcode formatting: 4-space indentation, braces on the same line, and SwiftUI views defined as `struct` types conforming to `View`. Use PascalCase for types (`ContentView`) and lowerCamelCase for properties and methods. Keep filenames aligned with their primary type (e.g., `PICCP_ServerApp.swift`). Asset names should match the identifiers referenced in code and stay in the app’s `Assets.xcassets` catalog.

## Testing Guidelines
There are no automated tests in this repo today. If you add tests, use XCTest targets (e.g., `PICCP Messaging ClientTests/`) and name files `*Tests.swift`. Example command: `xcodebuild test -project "PICCP Messaging Client/PICCP Messaging Client.xcodeproj" -scheme "Noctyra" -destination "platform=iOS Simulator,name=iPhone 15"`.

## Commit & Pull Request Guidelines
This directory does not contain Git history, so there is no established commit convention. If you introduce one, keep messages short and imperative (e.g., `Add login view`) and consider adding a scope for clarity. PRs should include a concise summary, testing notes (or “not run”), and screenshots for UI changes. Link any relevant documentation updates in `PICCP Documentation/`.
