// Spike S5: decodes every frame of the Rust stream with protoc_plugin's
// generated types and writes each one back out, framed the same way. The
// Rust test then requires the output to be byte-identical to its input.
//
// Usage: dart run bin/round_trip.dart <input.bin> <output.bin>
// The generated code is written to lib/gen by the CI job (protoc --dart_out).

import 'dart:io';
import 'dart:typed_data';

import 'package:mesh_ui_protocol_dart/gen/mesh/ui/v1/spike.pb.dart';

void main(List<String> args) {
  if (args.length != 2) {
    stderr.writeln('usage: round_trip.dart <input.bin> <output.bin>');
    exit(2);
  }
  final input = File(args[0]).readAsBytesSync();
  final view = ByteData.sublistView(input);
  final output = BytesBuilder();
  var offset = 0;
  var frames = 0;
  while (offset < input.length) {
    // u32 big-endian length, then the envelope.
    final length = view.getUint32(offset, Endian.big);
    final body = input.sublist(offset + 4, offset + 4 + length);
    offset += 4 + length;
    final again = Envelope.fromBuffer(body).writeToBuffer();
    final prefix = ByteData(4)..setUint32(0, again.length, Endian.big);
    output.add(prefix.buffer.asUint8List());
    output.add(again);
    frames++;
  }
  File(args[1]).writeAsBytesSync(output.toBytes());
  print('dart: $frames frames re-encoded');
}
