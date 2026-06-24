import Foundation
import NIOCore
import NIOFoundationCompat

enum LineCodecError: Error {
    case lineTooLong
}

final class LineDecoder: ByteToMessageDecoder {
    typealias InboundOut = ByteBuffer
    private let maxLength: Int?

    init(maxLength: Int? = nil) {
        self.maxLength = maxLength
    }

    func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard let newlineIndex = buffer.readableBytesView.firstIndex(of: 0x0A) else {
            if let maxLength, buffer.readableBytes > maxLength {
                context.close(promise: nil)
                throw LineCodecError.lineTooLong
            }
            return .needMoreData
        }
        let length = buffer.readerIndex.distance(to: newlineIndex)
        if let maxLength, length > maxLength {
            context.close(promise: nil)
            throw LineCodecError.lineTooLong
        }
        guard let line = buffer.readSlice(length: length) else {
            return .needMoreData
        }
        buffer.moveReaderIndex(forwardBy: 1)
        context.fireChannelRead(wrapInboundOut(line))
        return .continue
    }
}

final class LineEncoder {
    static func wrap(_ data: Data, into buffer: inout ByteBuffer) {
        buffer.writeBytes(data)
        buffer.writeInteger(UInt8(0x0A))
    }
}
