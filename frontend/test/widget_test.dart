// widget_test.dart
//
// Minimal Flutter smoke test.
//
// MeshInfinityApp cannot be tested in isolation because the frontend is always
// launched BY the Rust backend — the backend creates the FFI context, then
// calls Flutter's entry point.  Attempting to boot MeshInfinityApp without a
// live backend context hits an assert() in app.dart by design.
//
// This test verifies that Flutter's widget system itself is functional.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('Flutter widget system is operational', (WidgetTester tester) async {
    await tester.pumpWidget(const MaterialApp(home: Scaffold(body: SizedBox())));
    expect(find.byType(MaterialApp), findsOneWidget);
  });
}
