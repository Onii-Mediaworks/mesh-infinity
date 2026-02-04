import 'package:flutter_test/flutter_test.dart';

import 'package:mesh_infinity_frontend/app/app.dart';

void main() {
  testWidgets('App builds', (tester) async {
    await tester.pumpWidget(const MeshInfinityApp());
    expect(find.textContaining('Mesh Infinity'), findsOneWidget);
  });
}
