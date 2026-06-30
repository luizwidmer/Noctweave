import Foundation
@preconcurrency import NIOCore
@preconcurrency import NIOFoundationCompat

enum LineCodecError: Error {
    case lineTooLong
}

final class NIOContextBox: @unchecked Sendable {
    let context: ChannelHandlerContext

    init(_ context: ChannelHandlerContext) {
        self.context = context
    }
}

final class LineFrameHandler: ChannelDuplexHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let maxLength: Int?
    private var pending: ByteBuffer?

    init(maxLength: Int? = nil) {
        self.maxLength = maxLength
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)
        if pending == nil {
            pending = context.channel.allocator.buffer(capacity: incoming.readableBytes)
        }
        pending?.writeBuffer(&incoming)
        emitAvailableLines(context: context)
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        context.fireChannelReadComplete()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.fireErrorCaught(error)
    }

    private func emitAvailableLines(context: ChannelHandlerContext) {
        guard var buffer = pending else {
            return
        }
        while let newlineIndex = buffer.readableBytesView.firstIndex(of: 0x0A) {
            let length = buffer.readerIndex.distance(to: newlineIndex)
            if let maxLength, length > maxLength {
                context.fireErrorCaught(LineCodecError.lineTooLong)
                context.close(promise: nil)
                pending = nil
                return
            }
            guard let line = buffer.readSlice(length: length) else {
                break
            }
            buffer.moveReaderIndex(forwardBy: 1)
            context.fireChannelRead(wrapInboundOut(line))
        }
        if let maxLength, buffer.readableBytes > maxLength {
            context.fireErrorCaught(LineCodecError.lineTooLong)
            context.close(promise: nil)
            pending = nil
            return
        }
        buffer.discardReadBytes()
        pending = buffer.readableBytes > 0 ? buffer : nil
    }
}

final class LineEncoder {
    static func wrap(_ data: Data, into buffer: inout ByteBuffer) {
        buffer.writeBytes(data)
        buffer.writeInteger(UInt8(0x0A))
    }
}
