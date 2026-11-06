import com.oniimediaworks.meshinfinity.protocol.v1.Envelope
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer

/**
 * Spike S5: decodes every frame of the Rust stream with Wire's generated
 * types and writes each one back out, framed the same way. The Rust test
 * then requires the output to be byte-identical to its input.
 *
 * Usage: RoundTrip <input.bin> <output.bin>
 */
fun main(args: Array<String>) {
    require(args.size == 2) { "usage: RoundTrip <input.bin> <output.bin>" }
    val input = ByteBuffer.wrap(File(args[0]).readBytes())
    val output = ByteArrayOutputStream()
    var frames = 0
    while (input.hasRemaining()) {
        // u32 big-endian length, then the envelope (ByteBuffer is big-endian by default).
        val length = input.int
        val body = ByteArray(length).also { input.get(it) }
        val envelope = Envelope.ADAPTER.decode(body)
        val again = Envelope.ADAPTER.encode(envelope)
        output.write(ByteBuffer.allocate(4).putInt(again.size).array())
        output.write(again)
        frames++
    }
    File(args[1]).writeBytes(output.toByteArray())
    println("kotlin: $frames frames re-encoded")
}
