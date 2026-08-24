<?php

declare(strict_types=1);

namespace Torxy\Tests\Unit\Core;

use OverflowException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use React\Stream\ThroughStream;
use RuntimeException;
use Throwable;
use Torxy\Core\RequestBodyReader;

final class RequestBodyReaderTest extends TestCase
{
    #[DataProvider('replayableSizes')]
    public function testDecidesWhetherABodyCanBeHeld(?int $size, bool $expected): void
    {
        self::assertSame($expected, RequestBodyReader::isReplayable($size));
    }

    /**
     * @return array<string, array{int|null, bool}>
     */
    public static function replayableSizes(): array
    {
        $limit = RequestBodyReader::MAX_REPLAYABLE_BYTES;

        return [
            'empty'                => [0, true],
            'one byte'             => [1, true],
            // The 64 KiB boundary is where react/http's own buffering used to silently
            // truncate; well inside the limit now.
            'sixty four kibibytes' => [65536, true],
            'one byte over 64 KiB' => [65537, true],
            'exactly at limit'     => [$limit, true],
            'one byte over limit'  => [$limit + 1, false],
            'far over limit'       => [104857600, false],
            // Chunked uploads announce no length, so there is no size to check against.
            'unknown length'       => [null, false],
        ];
    }

    public function testBuffersAStreamIntoASingleString(): void
    {
        $stream = new ThroughStream();
        $result = $this->settle(RequestBodyReader::buffer($stream, 1024));

        $stream->write('hello ');
        $stream->write('world');
        $stream->end();

        self::assertSame('hello world', $result->value);
    }

    public function testEmptyStreamBuffersToAnEmptyString(): void
    {
        $stream = new ThroughStream();
        $result = $this->settle(RequestBodyReader::buffer($stream, 1024));

        $stream->end();

        self::assertSame('', $result->value);
    }

    public function testPreservesBinaryContentIncludingNullBytes(): void
    {
        $payload = random_bytes(2048);

        $stream = new ThroughStream();
        $result = $this->settle(RequestBodyReader::buffer($stream, 4096));

        // Chunked the way a socket would deliver it, to prove reassembly is byte-exact.
        foreach (str_split($payload, 512) as $chunk) {
            $stream->write($chunk);
        }
        $stream->end();

        self::assertSame($payload, $result->value);
    }

    public function testStreamEndingExactlyAtTheLimitIsAccepted(): void
    {
        $stream = new ThroughStream();
        $result = $this->settle(RequestBodyReader::buffer($stream, 10));

        $stream->write('0123456789');
        $stream->end();

        self::assertSame('0123456789', $result->value);
    }

    /**
     * The whole point of the class: a body that outgrows its limit must fail loudly. Passing
     * a truncated body upstream under the client's own Content-Length is the silent data loss
     * this replaces.
     */
    public function testRejectsRatherThanTruncatingWhenTheLimitIsExceeded(): void
    {
        $stream = new ThroughStream();
        $result = $this->settle(RequestBodyReader::buffer($stream, 10));

        $stream->write('0123456789X');

        self::assertInstanceOf(OverflowException::class, $result->error);
        self::assertNull($result->value);
    }

    public function testStopsReadingOnceTheLimitIsExceeded(): void
    {
        $stream = new ThroughStream();
        $result = $this->settle(RequestBodyReader::buffer($stream, 4));

        $stream->write('aaaaa');

        self::assertInstanceOf(OverflowException::class, $result->error);

        // Further writes must not revive the promise or grow a buffer nobody will read.
        $stream->write('bbbbb');
        $stream->end();

        self::assertInstanceOf(OverflowException::class, $result->error);
        self::assertNull($result->value);
    }

    public function testStreamErrorRejectsWithTheUnderlyingError(): void
    {
        $failure = new RuntimeException('connection reset');

        $stream = new ThroughStream();
        $result = $this->settle(RequestBodyReader::buffer($stream, 1024));

        $stream->write('partial');
        $stream->emit('error', [$failure]);

        self::assertSame($failure, $result->error);
    }

    /**
     * A client that disappears mid-upload closes the stream without ending it. Left
     * unhandled the promise would never settle and the request would hang forever.
     */
    public function testCloseWithoutEndRejects(): void
    {
        $stream = new ThroughStream();
        $result = $this->settle(RequestBodyReader::buffer($stream, 1024));

        $stream->write('half an upload');
        $stream->close();

        self::assertInstanceOf(RuntimeException::class, $result->error);
    }

    public function testCloseAfterEndKeepsTheBufferedValue(): void
    {
        $stream = new ThroughStream();
        $result = $this->settle(RequestBodyReader::buffer($stream, 1024));

        // ThroughStream::end() emits `end` and then `close`; the close must not overwrite
        // the value the end already resolved with.
        $stream->end('complete');

        self::assertSame('complete', $result->value);
        self::assertNull($result->error);
    }

    /**
     * Record how a promise settled, so tests can assert on it without a running event loop.
     * ThroughStream emits synchronously, which is what makes this possible.
     *
     * @param \React\Promise\PromiseInterface<string> $promise
     */
    private function settle(\React\Promise\PromiseInterface $promise): object
    {
        $result = new class {
            public ?string $value = null;
            public ?Throwable $error = null;
        };

        $promise->then(
            function (string $value) use ($result): void {
                $result->value = $value;
            },
            function (Throwable $e) use ($result): void {
                $result->error = $e;
            }
        );

        return $result;
    }
}
