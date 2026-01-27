import 'package:flutter_test/flutter_test.dart';

import 'package:net_infinity_frontend/app/app.dart';

void main() {
  testWidgets('App builds', (tester) async {
    await tester.pumpWidget(const NetInfinityApp());
    expect(find.textContaining('NetInfinity'), findsOneWidget);
  });
}
