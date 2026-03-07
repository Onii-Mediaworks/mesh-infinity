import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:mesh_infinity_frontend/app/app.dart';
import 'package:mesh_infinity_frontend/backend/backend_bridge.dart';

void main() {
  testWidgets('App boots', (WidgetTester tester) async {
    final bridge = BackendBridge.open(allowMissing: true);
    await tester.pumpWidget(MeshInfinityApp(bridge: bridge));
    expect(find.byType(MaterialApp), findsOneWidget);
  });
}
